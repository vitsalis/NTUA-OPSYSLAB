/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Your name here >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor = state->sensor;
	uint16_t ret = 0;
	
	spin_lock(&sensor->lock);
	if (state->buf_timestamp < sensor->msr_data[state->type]->last_update) {
		ret = 1;
	}
	spin_unlock(&sensor->lock);
	return ret;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint16_t num = 0;
	uint32_t timestamp = 0;
	char name[10];
	
	sensor = state->sensor;
	debug("leaving\n");

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	/* Why use spinlocks? We use spinlocks here because we're in interrupt context */
	spin_lock(&sensor->lock);

	num = sensor->msr_data[state->type]->values[0];
	timestamp = sensor->msr_data[state->type]->last_update;

	spin_unlock(&sensor->lock);

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	 // snprintf to avoid buffer overflows
	switch (state->type) {
		case BATT:
			sprintf(name, "BATT");
			num = lookup_voltage[num];
			break;
		case TEMP:
			sprintf(name, "TEMP");
			num = lookup_temperature[num];
			break;
		case LIGHT:
			sprintf(name, "LIGHT");
			num = lookup_light[num];
			break;
		case N_LUNIX_MSR:
			break;
	}
	state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%s=%d.%d\n", name, num / 1000, num % 1000);
	state->buf_timestamp = timestamp;

	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

/* - If we don't implement this, open will always succeed.
 * We decide to implement this to initialize the device's code
 *
 * - Kernel sets filp.f_op to this devices file_operations on open
 *
 * - Kernel sets filp.private_data to null before calling device's open
 * In our case we will initialize it to point to lunix_chrdev_state_struct
 *
 * - The inode parameter corresponds to the file used to spawn this driver
 * We will use it to deduce which sensor is being used and what type of metric we will return.
 */
static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret;
	unsigned int minor;
	struct lunix_chrdev_state_struct *state;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;


	state = kzalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);

	if (!state) {
		debug("failed to allocate memory");
		ret = -ENOMEM;
		goto out;
	}

	minor = iminor(inode);
	if (minor / 8 >= lunix_sensor_cnt) {
		debug("failed to find a valid sensor");
		kfree(state);
		ret = -EINVAL;
		goto out;
	}

	state->type = minor % 8;
	state->sensor = &lunix_sensors[minor / 8];
	state->buf_lim = 0;
	state->buf_timestamp = 0;
	sema_init(&state->lock, 1);

	filp->private_data = state;
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

/* If not implemented will always succeed */
static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* Release memory */
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/*
	 * We return -EINVAL since we do not support any
	 * feature that can fall under between the read/write spectrum
	 */
	return -EINVAL;
}

/*
 * We can't dereference the buffer from userspace because:
 * 1) The pointer might not be valid while in kernel mode
 * 2) The page might not exist in ram and the kernel
 * 	is not allowed to generate page faults
 * 3) The pointer has been supplied by a user program,
 * 	so dereferencing it while in kernel mode opens
 * 	the door for security vulnerabilities.
 *
 * So, in order to move data to the userspace we'll use the function
 * `copy_to_user(usrbuf, from_buffer, cnt)`
 * Since copy_to_user might put the current process in sleep
 * (the buffer doesn't exist on RAM and has to be retrieved),
 * the code should be able to run concurrently.
 *
 * On a successfull read we have to update the f_pos of the file struct.
 *
 * The return value will be:
 * 1) If all of the requested bytes have been read, then the return value is cnt.
 * 2) If less than the requested bytes have been read, then the return value is the number of bytes read.
 * 3) If the value is 0 then EOF has been reached.
 * 4) If an error has occurred a negative value is returned.
 * If we don't have any data but data may appear later we put the process to sleep.
 */
static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret = 0;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;
	char data[LUNIX_CHRDEV_BUFSZ];
	ssize_t lim;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock state semaphore */
	if (down_interruptible(&state->lock)) {
		return -ERESTARTSYS;
	}

	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (!lunix_chrdev_state_needs_refresh(state)) {
			/*
			 * Couple of rules for sleeping:
			 * 1) Never sleep on an atomic context.
			 * 	It is illegal with spinlocks and
			 * 	legal with semaphores,
			 * 	but we should be very careful.
			 * 2) When you wake up you don't know for
			 * 	how long the process was sleeping.
			 * 	Meanwhile, another process might have been
			 * 	waiting for the same event, so we again need
			 * 	to check the conditions that led us to sleep.
			 * 3) Do not sleep unless assured that someone will wake you up.
			 *
			 * We will use wait_event_interruptible(sensor->wq, condition);
			 * We check the return value. A non-zero return means that
			 * the process was woken up by a signal, and we should
			 * return -ERESTARTSYS
			 *
			 * When lunix-sensors:lunix_sensor_update calls wake_up_interruptible
			 * our process will wake up.
			 */
			up(&state->lock);
			// if no block is specified ask to try again.
			if (filp->f_flags & O_NONBLOCK) {
				return -EAGAIN;
			}
			debug("Putting process to sleep\n");
			// wait for event
			if (wait_event_interruptible(sensor->wq, (lunix_chrdev_state_needs_refresh(state)))) {
				// We have been woken up by an event
				// Let the upper virtual filesystem (VFS) layer handle it.
				return -ERESTARTSYS;
			}
			// see if we can get the lock again
			if (down_interruptible(&state->lock)) {
				return -ERESTARTSYS;
			}
		}
		// ok data is here.
		lunix_chrdev_state_update(state);
	}

	if (state->buf_lim <= cnt) {
		lim = state->buf_lim;
		strncpy(data, state->buf_data, state->buf_lim);
	}
	else {
		// copy data starting from *f_pos to *f_pos + cnt
		for (lim = 0; lim < cnt && *f_pos + lim < state->buf_lim; ++lim) {
			data[lim] = state->buf_data[*f_pos + lim];
		}
		*f_pos += lim;
		// end of file, we need a new metric
		if (*f_pos >= state->buf_lim) {
			*f_pos = 0;
		}
	}
	ret = lim;
	if (copy_to_user(usrbuf, data, lim)) {
		ret = -EFAULT;
		goto out;
	}
out:
	/* Unlock */
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

/* we allow for llseek to be the default function */
static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	char name[] = "Lunix:TNG";
	
	debug("initializing character device\n");
	/*
	 * The kernel uses cdev data structures to represent char devices internally.
	 * Here we initialize the lunix_chrdev_cdev pointer to cdev
	 * and set its file operations to the file operations defined for this driver
	 */
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	/* Assign a major of LUNIX_CHRDEV_MAJOR and minor of 0 */
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/*
	 * Register our character device
	 */
	if ((ret = register_chrdev_region(dev_no, lunix_minor_cnt, name)) < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/*
	 * Now we need to let the kernel know that a new device exist by adding
	 * the cdev instance we have previously initialized.
	 */
	if ((ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt)) < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no = 0;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}

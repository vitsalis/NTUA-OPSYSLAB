/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;
	unsigned int *syscall_type;
	unsigned int num_out, num_in;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];

	num_out = num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}

	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	vq = crdev->vq;
	sema_init(&crdev->lock, 1);

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	down(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	while (virtqueue_get_buf(vq, &len) == NULL) {
		/* do nothing */;
	}
	up(&crdev->lock);

	/* If host failed to open() return -ENODEV. */
	if (*host_fd < 0) {
		ret = -ENODEV;
		goto fail;
	}
	crof->host_fd = *host_fd;

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	unsigned int *syscall_type;
	unsigned int num_out, num_in, len;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];

	num_out = num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &(crof->host_fd), sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	if (down_interruptible(&crdev->lock)) {
		return -ERESTARTSYS;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg,
	                   host_fd_sg, ioctl_cmd_sg, key_sg, src_sg, dst_sg, *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
#define KEY_SIZE 24
#define DATA_SIZE 16384
#define IV_SIZE 24
	int *retval, *host_fd, *send_cmd;
	int sessid;
	int res;
	struct crypt_op *cop;
	struct session_op *sop;
	unsigned int *syscall_type;
	unsigned char *key, *src, *dst, *iv;
	unsigned char *saved_cop_dst;

	debug("Entering");
	num_out = 0;
	num_in = 0;

	key = kzalloc(KEY_SIZE * sizeof(unsigned char), GFP_KERNEL);
	src = kzalloc(DATA_SIZE * sizeof(unsigned char), GFP_KERNEL);
	dst = kzalloc(DATA_SIZE * sizeof(unsigned char), GFP_KERNEL);
	saved_cop_dst = kzalloc(DATA_SIZE * sizeof(unsigned char), GFP_KERNEL);
	iv = kzalloc(IV_SIZE * sizeof(unsigned char), GFP_KERNEL);

	sop = kzalloc(sizeof(struct session_op), GFP_KERNEL);
	cop = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);

	if (!key || !src || !dst || !iv || !sop || !cop) {
		ret = -ENOMEM;
		goto fail;
	}

	//memset(sop, 0, sizeof(struct session_op));
	//memset(cop, 0, sizeof(struct crypt_op));

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	retval = kzalloc(sizeof(*retval), GFP_KERNEL);

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	send_cmd = kzalloc(sizeof(*send_cmd), GFP_KERNEL);
	*send_cmd = cmd;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	debug("Syscall type is %d", *syscall_type);

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	debug("host fd is %d", *host_fd);
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&ioctl_cmd_sg, send_cmd, sizeof(*send_cmd));
	debug("cmd is %u\n", *send_cmd);
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		if (copy_from_user(sop, (struct session_op __user *) arg, sizeof(struct session_op))) {
			ret = -EINVAL;
			goto fail;
		}
		if (copy_from_user(key, sop->key, sop->keylen)) {
			ret = -EINVAL;
			goto fail;
		}
		sg_init_one(&key_sg, key, sizeof(*key));
		sgs[num_out++] = &key_sg;

		sg_init_one(&input_msg_sg, retval, sizeof(*retval));
		sgs[num_out + num_in++] = &input_msg_sg;

		sg_init_one(&output_msg_sg, sop, sizeof(struct session_op));
		sgs[num_out + num_in++] = &output_msg_sg;

		debug("Initialized session with id %d\n", sop->ses);
		debug("Accessed the pointer to the struct");
		break;
	case CIOCFSESSION:
		debug("CIOCFSESSION");
		if (copy_from_user(&sessid, (void __user *) arg, sizeof(int))) {
			ret = -EINVAL;
			goto fail;
		}
		sg_init_one(&output_msg_sg, &sessid, sizeof(int));
		sgs[num_out++] = &output_msg_sg;

		sg_init_one(&input_msg_sg, retval, sizeof(*retval));
		sgs[num_out + num_in++] = &input_msg_sg;
		break;
	case CIOCCRYPT:
		debug("CIOCCRYPT");
		if (copy_from_user(cop, (void __user *) arg, sizeof(struct crypt_op))) {
			ret = -EINVAL;
			goto fail;
		}
		saved_cop_dst = cop->dst;
		if (copy_from_user(iv, cop->iv, IV_SIZE)) {
			ret = -EINVAL;
			goto fail;
		}
		if (copy_from_user(src, cop->src, DATA_SIZE)) {
			ret = -EINVAL;
			goto fail;
		}
		if (copy_from_user(dst, cop->dst, DATA_SIZE)) {
			ret = -EINVAL;
			goto fail;
		}

		sg_init_one(&output_msg_sg, cop, sizeof(struct crypt_op));
		sgs[num_out++] = &output_msg_sg;

		sg_init_one(&src_sg, src, sizeof(*src));
		sgs[num_out++] = &src_sg;

		sg_init_one(&key_sg, iv, sizeof(*iv));
		sgs[num_out++] = &key_sg;

		sg_init_one(&input_msg_sg, retval, sizeof(*retval));
		sgs[num_out + num_in++] = &input_msg_sg;

		sg_init_one(&dst_sg, dst, sizeof(*dst));
		sgs[num_out + num_in++] = &dst_sg;
		break;
	default:
		debug("Unsupported ioctl command");
		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	if (down_interruptible(&crdev->lock)) {
		return -ERESTARTSYS;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL) {
		/* do nothing */;
	}
	up(&crdev->lock);

	switch (cmd) {
	case CIOCGSESSION:
		if (copy_to_user((struct session_op __user *) arg, sop, sizeof(struct session_op))) {
			ret = -EINVAL;
			goto fail;
		}
		break;
	case CIOCCRYPT:
		if ((res = copy_to_user((unsigned char __user *)saved_cop_dst, dst, DATA_SIZE))) {
			ret = -EINVAL;
			goto fail;
		}
		break;
	default:
		break;
	}
	debug("Leaving");

	kfree(syscall_type);
	kfree(sop);
	kfree(cop);
	kfree(key);
	kfree(iv);
	kfree(src);
	kfree(dst);
fail:
	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}

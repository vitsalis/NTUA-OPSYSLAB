Challenge 0 - Hello there
=========================

After running `strace ./riddle` we see that it tries to open a file
`.hello_there`.

Solution: `touch .hello_there`

Challenge 1 - Gatekeeper
========================

After running `strace ./riddle` we see that it tries to open a file
`.hello_there` with `O_WRONLY` access rights.

Solution: `chmod -w .hello_there`

Challenge 2 - A time to kill
============================

After running `strace ./riddle` we see two calls to `rt_sigaction` a system
call used to change the action taken by a process on the receipt of a specific
signal.

The first call adds a new action for the SIGALARM signal, and the second adds
an action for the SIGCONT signal. We then see a system call to `pause`.

Solution: Before the `pause` system call ends send a `SIGCONT` signal via
`kill -SIGSTOP [pid]` where `[pid]` the process id of `riddle`.

Challenge 3 - what is the answer to life the universe and everything?
=====================================================================

After running `ltrace ./riddle` we see a call to `getenv("ANSWER")`.

Solution: `ANSWER=42 ./riddle`

Challenge 4 - First-in, First-out
=================================

After running `strace ./riddle` we see references to two environment variables
`I_HATE_GAME_HINTS` and `I_NEED_TECH_HINTS`. We set them to random values.

We run the riddle again and see a new hint.
We then run `strace` and see a call to `open("magic_mirror", O_RDWR)`, so
we create the file `magic_mirror` with read and write priviledges.

We run the riddle again with strace and see two new calls:
`write(4, "U", 1)` and `read(4, "", 1)`.

Solution: To view the hints: `I_HATE_GAME_HINTS=1 I_NEED_TECH_HINTS=2  ./riddle`
          To solve: `mkfifo magic_mirror`

Challenge 5 - my favourite fd is 99
===================================

We see that on the output of strace `fcntl(99, F_GETFD)` is called and fails.
We set the file descriptor to something and get appropriate output.

Solution: `./riddle 99>1`

Challenge 6 - ping pong
=======================

On the output of `strace -f` we see that two subprocesses try to communicate via file
descriptors 33,34 and 53,54. Specifically, the first process receives pings
from file descriptor 53 and the second via the file descriptor 33.
The first process uses file descriptor 34 to send pings and the second uses
file descriptor 54.

So, the process is clear, although difficult to implement:
We create two FIFO pipes, and and assign file descriptor 33 and 53 to those
pipes. We then redirect all output to file descriptors 34 and 54 to those
pipes. We have

Solution:
```
mkfifo ff1
mkfifo ff2
./riddle 33<> ff1 53<> ff2 34>&33 54>&53
```

Challenge 7 - What's in a name?
===============================

First we create the file `.hey_there` since we see that it is opened from
strace.

Then, we see from the output that it compares two numbers.
We also see from strace that `lstat` is called. We execute
`stat .hello_there && stat .hey_there` and see that the numbers that were
compared were the inode indexes for these files. So, since we want to have the
same inode number for both files, we create a hard link.

Solution: `ln .hello_there .hey_there`

Challenge 8 - Big Data
======================

We see on the output of strace that it tries to read a file "bf00". We create
that file and then see that it sets the seek to a really large number.
We create a soft link from `bf00` to `/dev/urandom/` and try again.

We now see that it tries the same thing with file `bf01`. So we execute
`for i in {0..9}; do ln -s /dev/urandom bf0$i; done` and try again
and we get a proper result.

Solution: `for i in {0..9}; do ln -s /dev/urandom bf0$i; done`

Challenge 9 - Connect
=====================

We see on the output of strace that it tries to connect to localhost on port
49842 and the connection is refused.

So we set up a netcat server listening on 49842 with
`nc -l -p 49842` and get the message sent.

Solution: `nc -l -p 49842`

Challenge 10 - ESP
==================

We see on the output of strace that a file "secret_number" is created and then
unliked. We know that unlink doesn't actually remove the data contained in the
inode of a file, but instead removes the reference to the inode.

If more references exist when a reference to the inode is removed, then that
inode isn't deleted. If the unlinked reference is the last one then that
inode is deleted.

So we want to have more than one references to the inode that the challenge
writes to. So we create a "tmp" file, hard link "secret_number" to it and then
execute. The answer resides on the "tmp" file.

Solution: `touch tmp; ln tmp secret_number; ./riddle`

Challenge 11 - ESP2
===================

We try the same trick as before but it seems that the number of links to the
inode is counted and if it is more than one, our answer is rejected.

So, we visit again the man page for `unlink` and see that the file is removed
if there are no more links to it, or another process isn't using it.

So we set up a simple C program that opens the file and after an interval
prints its contents in an endless loop and get the correct answer.

Solution:
```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
		int d, ans;
        char buffer[1000];

        d = open("secret_number", O_RDWR|O_CREAT|O_TRUNC, 0600);
        while (1) {
                ans = read(d, buffer, 100);
                printf("%s\n", buffer);
                sleep(10);
        }

        close(d);
}
```

Challenge 12 - A delicate change
================================

On the output of strace we see a call to nmap which returns the start of the
page. We see that it is a shared map so we can create another process which
modifies the mmapped memory. We see that the change needs to happen on the
location of 0x6f after the start of the page. So we run the following program,
which modifies the `111`th byte of the mmaped region:

```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

// argv[1] is the file that was used
// argv[2] is the start of the page
// argv[3] is the character we want to add to region[111]
int main(int argc, char **argv) {
        int d = open(argv[1], O_RDWR|O_CREAT|O_TRUNC, 0600);
        char *region = mmap(argv[2], 4096, PROT_READ|PROT_WRITE, MAP_SHARED, d, 0);

        posix_fallocate(d, 0, 4096);

        region[111] = argv[3][0];
        sleep(10);
        close(d);

        return 0;
}
```

Challenge 13 - Bus Error
========================

On the output of strace we see a call to `ftruncate` with size 32768,
then an `mmap` for that file and finally a call to `ftruncate` with size 16384.
Then, riddle expects an input.

Whatever input we give the program crashes with SIGBUS. This happens because
the file size is half of what has been mmaped, so if we access byte 16385, we
get a SIGBUS since this byte is outside of the file's region.

So, while waiting for input truncate the file to its intended size 32768.

Solution: `truncate -s 32768 .hello_there`

Challenge 14 - Are you the One?
===============================

In this case the process expectes to have a pid of "32767". processes get their
ids from `/proc/sys/kernel/ns_last_pid` so:

Solution: `echo "32767" > /proc/sys/kernel/ns_last_pid | ./riddle`

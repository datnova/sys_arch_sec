# Lab 1: Linux Capability Exploration Lab

## Lab Setup
Install Ubuntu 16.04: https://releases.ubuntu.com/16.04/


## Install Libcap
In Ubuntu 16.04 libcap library already been installed

```bash
# install additional
$ apt-get install wget

# save download location
$ mkdir lib_resource
$ cd lib_resource

# download and extract libcap
$ wget http://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2. 21.tar.gz
$ tar xvf libcap-2.21.tar.gz
$ cd libcap-2.21

# if you are running in ubuntu 16.04, run these two commands
$ sudo apt-get update
$ sudo apt-get install libattr1-dev

# compile libcap
$ make
$ make install
```


## Put SELinux in Permissive Mode
If you dont have "/etc/selinux/config" then run this command to install:
```bash
$ sudo apt-get install selinux
```

change a line in file into this:
```
SELINUX=permissive
```


## __Task 1__
Turn Set-UID program into non-Set-UID program.
```bash
$ sudo chmod u-s /bin/ping

# reverse back to normal
$ sudo chmod u+s /bin/ping 
```
After set non-Set-UID propram when run command "ping google.com", it return error.

You need to set cap_net_raw capability to "ping".
```bash
$ sudo setcap cap_net_raw=ep /bin/ping
$ ping google.com

# reverse back to normal
$ sudo setcap cap_net_raw-ep /bin/ping
```


__Question 1:__
```bash
# turn setuid program into non-setuid program
$ sudo chmod u-s /usr/bin/passwd

# use the setcap command to assign capabilities to a file
# give process capabilities (special privileges) without giving it full root access
$ sudo setcap cap_dac_override=ep /usr/bin/passwd   
```

__Question 2__
- __cap_dac_read_search__: This capability allows a process to bypass file read permission checks and directory read and execute permission check. For example, a process with this capability can read any file on the system, even if it is owned by another user or has no read permission for others. A program that demonstrates this capability is getcap, which can list the capabilities of any file on the system if it has cap dac read search enabled.

- __cap_dac_override__: This capability allows a process to bypass file write, execute, and delete permission check. For example, a process with this capability can modify or remove any file on the system, even if it is owned by another user or has no write permission for others. A program that demonstrates this capability is setcap, which can set or clear the capabilities of any file on the system if it has cap dac override enabled.

- __cap_chown__: This capability allows a process to make arbitrary changes to file UIDs and GID. For example, a process with this capability can change the owner or group of any file on the system, even if it is not the owner of the file or a member of the group. A program that demonstrates this capability is chown, which can change the owner or group of any file on the system if it has cap chown enabled.

- __cap_setuid__: This capability allows a process to change its effective user ID (EUID) and effective group ID (EGID) without restriction. For example, a process with this capability can switch to any user or group on the system, even if it is not related to them by password file entries. A program that demonstrates this capability is su, which can switch to any user on the system if it has cap setuid enabled.

- __cap_kill__: This capability allows a process to send signals to other processes without restriction. For example, a process with this capability can kill any other process on the system, even if it is owned by another user or has higher privileges. A program that demonstrates this capability is kill, which can send signals to any process on the system if it has cap kill enabled.

- __cap_net_raw__: This capability allows a process to use raw socket. Raw sockets allow direct access to lower-level network protocols, such as ICMP or ARP. For example, a process with this capability can send or receive packets without any processing by the kernel network stack. A program that demonstrates this capability is ping, which can send ICMP echo requests and receive ICMP echo replies if it has cap net raw enabled.


## __Task 2__

add these lines of code into this file "libcap-2.21/libcap/cap_proc.c"  

```c
int cap_disable(cap_value_t capflag)
{
    cap_t mycaps;
    mycaps = cap_get_proc();
    if (mycaps == NULL)
        return -1;
    if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
    if (cap_set_proc(mycaps) != 0)
        return -1;
    return 0;
}

int cap_enable(cap_value_t capflag)
{
    cap_t mycaps;
    mycaps = cap_get_proc();
    if (mycaps == NULL)
        return -1;
    if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_SET) != 0)
        return -1;
    if (cap_set_proc(mycaps) != 0)
        return -1;
    return 0;
}
int cap_drop(cap_value_t capflag)
{
    cap_t mycaps;
    mycaps = cap_get_proc();
    if (mycaps == NULL)
        return -1;
    if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
    if (cap_set_flag(mycaps, CAP_PERMITTED, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
    if (cap_set_proc(mycaps) != 0)
        return -1;
    return 0;
}
```
After that, compile and install modifiled lib:
```bash
$ make
$ make install
```

__Question 3__

Create file "use_cap.c".
```c
/* use_cap.c  */
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/capability.h>
#include <sys/capability.h>

int main(void)
{
    if (open ("/etc/shadow", O_RDONLY) < 0)
        printf("(a) Open failed\n");
    /* Question (a): is the above open sucessful? why? */

    if (cap_disable(CAP_DAC_READ_SEARCH) < 0) return -1;
    if (open ("/etc/shadow", O_RDONLY) < 0)
        printf("(b) Open failed\n");
    /* Question (b): is the above open sucessful? why? */

    if (cap_enable(CAP_DAC_READ_SEARCH) < 0) return -1;
    if (open ("/etc/shadow", O_RDONLY) < 0)
        printf("(c) Open failed\n");

    /* Question (c): is the above open sucessful? why?*/

    if (cap_drop(CAP_DAC_READ_SEARCH) < 0) return -1;
    if (open ("/etc/shadow", O_RDONLY) < 0)
        printf("(d) Open failed\n");
    /* Question (d): is the above open sucessful? why?*/

    if (cap_enable(CAP_DAC_READ_SEARCH) == 0) return -1;
    if (open ("/etc/shadow", O_RDONLY) < 0)
        printf("(e) Open failed\n");
    /* Question (e): is the above open sucessful? why?*/
}
```

After that, compile the file.
```bash
$ gcc -c use_cap.c
$ gcc -o use_cap use_cap.o -lcap
```

Assign the *cap_dac_read_search* capability to the executable
```bash
$ sudo setcap cap_dac_read_search=ep use_cap 
```

- __Question a__: The first open call may or may not be successful, depending on the effective user ID (EUID) of the process and the file permissions of /etc/shadow. If the EUID is 0 (root), then the open call will succeed regardless of the file permissions, because root has CAP_DAC_READ_SEARCH capability by default. If the EUID is not 0, then the open call will only succeed if the file permissions allow read access for others (e.g., 644 or 444). Otherwise, the open call will fail with permission denied error.

- __Question b__: The second open call will always fail, regardless of the EUID and the file permissions, because cap_disable(CAP_DAC_READ_SEARCH) disables the CAP_DAC_READ_SEARCH capability for the process. This means that the process cannot bypass file read permission checks and directory read and execute permission checks anymore. Therefore, the open call will fail with permission denied error.

- __Question c__: The third open call may or may not be successful, depending on the EUID and the file permissions, similar to question (a). This is because cap_enable(CAP_DAC_READ_SEARCH) re-enables the CAP_DAC_READ_SEARCH capability for the process, which means that the process can bypass file read permission checks and directory read and execute permission checks again. Therefore, if the EUID is 0 or the file permissions allow read access for others, then the open call will succeed. Otherwise, it will fail with permission denied error.

- __Question d__: The fourth open call will always fail, regardless of the EUID and the file permissions, because cap_drop(CAP_DAC_READ_SEARCH) drops (removes) the CAP_DAC_READ_SEARCH capability from the process’s bounding set. This means that even if cap_enable(CAP_DAC_READ_SEARCH) is called later, it will have no effect. Therefore, the process cannot bypass file read permission checks and directory read and execute permission checks anymore. Hence, the open call will fail with permission denied error.

- __Question e__: The fifth open call will never be executed, because cap_enable(CAP_DAC_READ_SEARCH) will always return -1 and cause the program to exit with an error code. This is because cap_enable(CAP_DAC_READ_SEARCH) can only enable a capability that is already in the process’s bounding set, but cap_drop(CAP_DAC_READ_SEARCH) has removed it from there in __question d__. Therefore, cap_enable(CAP_DAC_READ_SEARCH) will fail with invalid argument error and terminate the program.
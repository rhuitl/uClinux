#
# Makefile of Linux specific functions for m68k
#

TOPDIR=../../..

include $(TOPDIR)/Makeconfig
include $(TOPDIR)/Makerules

INC_CFLAGS=-I$(TOPDIR) -I.

ifeq ($(MATH),true)
 
lib all:
	($(MAKE) -C math $@)

else

DIRS:=math crt

ifeq ($(PROFILE),true)
DIRS:=$(DIRS) gmon
endif

SRC1S = __brk.c  __sbrk.c __select.c __sigact.c getprio.c \
	ptrace.c readdir.c sigsuspend.c syscall.c libc_exit.c \
	__setfpucw.c __fpu_control.c __init_brk.c readdir_r.c
# __load.c __adjtime.c __ntpgttm.c __wait.c __wait3.c __waitpid.c
# accept.c bind.c msgget.c msgrcv.c msgsnd.c msgctl.c semget.c
# semop.c semctl.c listen.c mmap.c socket.c socketpair.c tell.c
# ulimit.c recv.c revcfrom.c send.c sendto.c setpgrp.c setsockopt.c
# shutdown.c connect.c getpeernam.c getsocknam.c getsockopt.c
# shmget.c shmat.c shmdt.c shmctl.c
#SRC2S = __vfork.c vfork.c
SRC3S = ____sig.S vfork.S # __adjtimex.S

SRCS= $(SRC1S) $(SRC2S) $(SRC3S)
ASMS= $(SRC1S:.c=.s) $(SRC2S:.c=.s) $(SRC3S:.S=.s)
OBJS= $(SRC1S:.c=.o) $(SRC3S:.S=.o)
ALIASES= $(SRC2S:.c=.o)

include $(TOPDIR)/Maketargets

ifeq ($(STATIC),true)

#LIBIEEE=$(STATIC_DIR)/libieee.a

#lib:: $(LIBIEEE)

$(STATIC_DIR)/$(SUBDIR)/ieee.o: ieee.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBIEEE): $(STATIC_DIR)/$(SUBDIR)/ieee.o
	$(RM) -f $(LIBIEEE)
	$(AR) $(AR_FLAGS) $(LIBIEEE) $?
	$(REALRANLIB) $(LIBIEEE)
endif

endif

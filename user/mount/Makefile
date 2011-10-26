
MOUNT = mount
UMOUNT = umount
OBJS = fstab.o lomount.o mntent.o nfsmount.o nfsmount_clnt.o \
	nfsmount_xdr.o realpath.o sundries.o version.o

CFLAGS += -DHAVE_NFS

all: $(MOUNT) $(UMOUNT)

$(MOUNT): mount.o $(OBJS)
	$(CC) $(LDFLAGS) -o $@ mount.o $(OBJS) $(LDLIBS)

$(UMOUNT): umount.o $(OBJS)
	$(CC) $(LDFLAGS) -o $@ umount.o $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_MOUNT_MOUNT /bin/$(MOUNT)
	$(ROMFSINST) -e CONFIG_USER_MOUNT_UMOUNT /bin/$(UMOUNT)

clean:
	-rm -f $(MOUNT) $(UMOUNT) *.elf *.gdb *.o


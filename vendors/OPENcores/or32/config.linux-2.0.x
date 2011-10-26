#
# Automatically generated make config: don't edit
#
CONFIG_UCLINUX=y

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y

#
# Platform dependant setup
#
CONFIG_OR32=y

#
# Platform
#
CONFIG_GEN=y
# CONFIG_RAMKERNEL is not set
CONFIG_ROMKERNEL=y

#
# General setup
#
# CONFIG_PCI is not set
CONFIG_NET=y
# CONFIG_SYSVIPC is not set
CONFIG_REDUCED_MEMORY=y
CONFIG_BINFMT_FLAT=y
# CONFIG_BINFMT_ELF is not set
CONFIG_KERNEL_ELF=y
# CONFIG_CONSOLE is not set

#
# Floppy, IDE, and other block devices
#
CONFIG_BLK_DEV_BLKMEM=y
# CONFIG_BLK_DEV_IDE is not set

#
# Additional Block/FLASH Devices
#
# CONFIG_BLK_DEV_LOOP is not set
# CONFIG_BLK_DEV_MD is not set
CONFIG_BLK_DEV_RAM=y
# CONFIG_RD_RELEASE_BLOCKS is not set
# CONFIG_BLK_DEV_INITRD is not set
# CONFIG_DEV_FLASH is not set

#
# Networking options
#
# CONFIG_FIREWALL is not set
# CONFIG_NET_ALIAS is not set
CONFIG_INET=y
# CONFIG_IP_FORWARD is not set
# CONFIG_IP_MULTICAST is not set
# CONFIG_SYN_COOKIES is not set
# CONFIG_IP_ACCT is not set
# CONFIG_IP_ROUTER is not set
# CONFIG_NET_IPIP is not set

#
# (it is safe to leave these untouched)
#
# CONFIG_INET_PCTCP is not set
# CONFIG_INET_RARP is not set
# CONFIG_NO_PATH_MTU_DISCOVERY is not set
# CONFIG_IP_NOSR is not set
# CONFIG_SKB_LARGE is not set

#
#  
#
# CONFIG_IPX is not set
# CONFIG_ATALK is not set
# CONFIG_AX25 is not set
# CONFIG_BRIDGE is not set
# CONFIG_NETLINK is not set
# CONFIG_IPSEC is not set

#
# Network device support
#
CONFIG_NETDEVICES=y
# CONFIG_DUMMY is not set
# CONFIG_SLIP is not set
# CONFIG_PPP is not set
# CONFIG_EQUALIZER is not set
# CONFIG_OETH is not set

#
# Filesystems
#
# CONFIG_QUOTA is not set
# CONFIG_MINIX_FS is not set
# CONFIG_EXT_FS is not set
CONFIG_EXT2_FS=y
# CONFIG_XIA_FS is not set
# CONFIG_NLS is not set
CONFIG_PROC_FS=y
# CONFIG_NFS_FS is not set
# CONFIG_SMB_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_SYSV_FS is not set
# CONFIG_AUTOFS_FS is not set
# CONFIG_AFFS_FS is not set
CONFIG_ROMFS_FS=y
# CONFIG_JFFS_FS is not set
# CONFIG_UFS_FS is not set

#
# Character devices
#
CONFIG_SERIAL=y
# CONFIG_WATCHDOG is not set
# CONFIG_KEYBOARD is not set

#
# Kernel hacking
#
# CONFIG_PROFILE is not set

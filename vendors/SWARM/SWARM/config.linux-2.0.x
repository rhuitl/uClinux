#
# Automatically generated make config: don't edit
#
CONFIG_ARM=y
CONFIG_UCLINUX=y
MAGIC_ROM_PTR=y

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y

#
# Loadable module support
#
# CONFIG_MODULES is not set

#
# General setup
#
# CONFIG_ARCH_TRIO is not set
CONFIG_ARCH_AT91=y
# CONFIG_ARCH_NETARM is not set
# CONFIG_ARCH_ARC is not set
# CONFIG_ARCH_A5K is not set
# CONFIG_ARCH_RPC is not set
# CONFIG_ARCH_EBSA110 is not set
# CONFIG_ARCH_NEXUSPCI is not set
# CONFIG_ARCH_GBA is not set
# CONFIG_ARCH_ACORN is not set
# CONFIG_PCI is not set
CONFIG_ARCH_ATMEL=y
CONFIG_CPU_ARM7=y
CONFIG_ARM_CLK=32768000
DRAM_BASE=02000000
DRAM_SIZE=00100000
FLASH_MEM_BASE=01000000
FLASH_SIZE=00100000
# CONFIG_EBI is not set
# CONFIG_ARCH_ATMEL_EB55 is not set
# CONFIG_WILL_BOOT_FROM_FLASH is not set
# CONFIG_FRAME_POINTER is not set
CONFIG_BINUTILS_NEW=y
# CONFIG_DEBUG_ERRORS is not set
CONFIG_NET=y
# CONFIG_SYSVIPC is not set
CONFIG_REDUCED_MEMORY=y
CONFIG_BINFMT_FLAT=y
CONFIG_KERNEL_ELF=y
# CONFIG_BINFMT_JAVA is not set

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
# CONFIG_DEV_FLASH is not set

#
# Character devices
#
CONFIG_SERIAL_ATMEL=y
# CONFIG_CONSOLE_ON_ATMEL is not set
# CONFIG_SWAP_ATMEL_PORTS is not set
USART0_BASE=FFFD0000
USART1_BASE=FFFCC000
# CONFIG_SC28L91 is not set
# CONFIG_SERIAL_ATMEL_BT is not set
# CONFIG_LED_ATMEL is not set

#
# Networking options
#
# CONFIG_FIREWALL is not set
# CONFIG_NET_ALIAS is not set
CONFIG_INET=y
CONFIG_IP_FORWARD=y
# CONFIG_IP_MULTICAST is not set
# CONFIG_SYN_COOKIES is not set
# CONFIG_IP_ACCT is not set
CONFIG_IP_ROUTER=y
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
CONFIG_SLIP=y
CONFIG_SLIP_COMPRESSED=y
# CONFIG_SLIP_SMART is not set
# CONFIG_SLIP_MODE_SLIP6 is not set
CONFIG_PPP=y

#
# CCP compressors for PPP are only built as modules.
#
# CONFIG_EQUALIZER is not set
# CONFIG_UCCS8900 is not set
# CONFIG_SMC9194 is not set
# CONFIG_NE2000 is not set

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
CONFIG_NFS_FS=y
# CONFIG_ROOT_NFS is not set
# CONFIG_SMB_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_SYSV_FS is not set
# CONFIG_AUTOFS_FS is not set
# CONFIG_AFFS_FS is not set
CONFIG_ROMFS_FS=y
# CONFIG_JFFS_FS is not set
# CONFIG_UFS_FS is not set

#
# Kernel hacking
#
# CONFIG_PROFILE is not set

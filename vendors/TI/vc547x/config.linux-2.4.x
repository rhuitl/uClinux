#
# Automatically generated make config: don't edit
#
CONFIG_ARM=y
# CONFIG_SBUS is not set
CONFIG_UID16=y
CONFIG_RWSEM_GENERIC_SPINLOCK=y
CONFIG_UCLINUX=y
MAGIC_ROM_PTR=y

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y
CONFIG_OBSOLETE=y

#
# Loadable module support
#
CONFIG_MODULES=y
# CONFIG_MODVERSIONS is not set
CONFIG_KMOD=y

#
# System Type
#
# CONFIG_ARCH_DSC21 is not set
CONFIG_ARCH_VC547X=y
# CONFIG_ARCH_DM270 is not set
# CONFIG_ARCH_CNXT is not set
# CONFIG_ARCH_NETARM is not set
# CONFIG_ARCH_TA7S is not set
# CONFIG_ARCH_TA7V is not set
# CONFIG_ARCH_SWARM is not set
# CONFIG_ARCH_INL is not set
# CONFIG_ARCH_SAMSUNG is not set
# CONFIG_ARCH_LPC is not set
# CONFIG_MACH_EB67XDIP is not set
# CONFIG_ARCH_ATMEL is not set
# CONFIG_MACH_UC5471DSP is not set
# CONFIG_MACH_SJ5471ENG is not set
# CONFIG_ARCH_IPOD is not set
# CONFIG_ARCH_WINBOND is not set
# CONFIG_CPU_BIG_ENDIAN is not set
CONFIG_SET_MEM_PARAM=y
DRAM_BASE=0x10000000
DRAM_SIZE=0x01000000
FLASH_MEM_BASE=0x00000000
FLASH_SIZE=0x00800000
CONFIG_RAMKERNEL=y
# CONFIG_ROMKERNEL is not set
CONFIG_CPU_ARM710=y
CONFIG_CPU_ARM7TDMI=y
CONFIG_CPU_32=y
CONFIG_CPU_32v4=y
# CONFIG_CPU_26 is not set
CONFIG_NO_PGT_CACHE=y
CONFIG_CPU_WITH_CACHE=y
# CONFIG_CPU_WITH_MCR_INSTRUCTION is not set
CONFIG_DUMMY_CONSOLE=y

#
# General setup
#
# CONFIG_HOTPLUG is not set
# CONFIG_PCMCIA is not set
CONFIG_NET=y
# CONFIG_SYSVIPC is not set
# CONFIG_REDUCED_MEMORY is not set
# CONFIG_BSD_PROCESS_ACCT is not set
CONFIG_SYSCTL=y
# CONFIG_NWFPE is not set
# CONFIG_KCORE_ELF is not set
CONFIG_KCORE_AOUT=y
CONFIG_BINFMT_FLAT=y
# CONFIG_BINFMT_ZFLAT is not set
CONFIG_KERNEL_ELF=y
# CONFIG_PM is not set
# CONFIG_ARTHUR is not set
# CONFIG_ALIGNMENT_TRAP is not set
# CONFIG_PCI is not set
# CONFIG_RAM_ATTACHED_ROMFS is not set

#
# Networking options
#
# CONFIG_PACKET is not set
# CONFIG_NETLINK_DEV is not set
# CONFIG_NETFILTER is not set
# CONFIG_FILTER is not set
# CONFIG_NET_NEIGH_DEBUG is not set
# CONFIG_NET_RESTRICTED_REUSE is not set
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_MULTIPLE_TABLES=y
# CONFIG_IP_ROUTE_BIG_RT_CACHE is not set
# CONFIG_IP_ROUTE_NAT is not set
CONFIG_IP_ROUTE_MULTIPATH=y
# CONFIG_IP_ROUTE_MULTIPATH_SEQUENTIAL is not set
CONFIG_IP_ROUTE_TOS=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
CONFIG_IP_PNP_BOOTP=y
CONFIG_IP_PNP_RARP=y
# CONFIG_NET_ARP_LIMIT is not set
CONFIG_NET_IPIP=y
CONFIG_NET_IPGRE=y
CONFIG_NET_IPGRE_BROADCAST=y
CONFIG_IP_MROUTE=y
# CONFIG_IP_PIMSM_V1 is not set
# CONFIG_IP_PIMSM_V2 is not set
# CONFIG_ARPD is not set
# CONFIG_INET_ECN is not set
# CONFIG_SYN_COOKIES is not set
# CONFIG_IPV6 is not set
# CONFIG_KHTTPD is not set

#
#    SCTP Configuration (EXPERIMENTAL)
#
# CONFIG_IP_SCTP is not set
# CONFIG_ATM is not set
# CONFIG_VLAN_8021Q is not set

#
#  
#
# CONFIG_IPX is not set
# CONFIG_ATALK is not set
# CONFIG_DECNET is not set
# CONFIG_BRIDGE is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_LLC is not set
# CONFIG_NET_DIVERT is not set
# CONFIG_ECONET is not set
# CONFIG_WAN_ROUTER is not set
# CONFIG_NET_FASTROUTE is not set
# CONFIG_NET_HW_FLOWCONTROL is not set

#
# QoS and/or fair queueing
#
# CONFIG_NET_SCHED is not set
# CONFIG_IPSEC is not set
# CONFIG_KLIPS is not set

#
# Network testing
#
# CONFIG_NET_PKTGEN is not set
# CONFIG_IPSEC_NAT_TRAVERSAL is not set

#
# Network device support
#
CONFIG_NETDEVICES=y

#
# ARCnet devices
#
# CONFIG_ARCNET is not set
# CONFIG_DUMMY is not set
# CONFIG_BONDING is not set
# CONFIG_EQUALIZER is not set

#
# IMQ needs CONFIG_NETFILTER enabled
#
# CONFIG_TUN is not set
# CONFIG_ETHERTAP is not set

#
# Ethernet (10 or 100Mbit)
#
CONFIG_NET_ETHERNET=y
# CONFIG_ARM_AM79C961A is not set
# CONFIG_ARM_CIRRUS is not set
CONFIG_C5471_NET=y
C5471_LAN_RATE=0
# CONFIG_SUNLANCE is not set
# CONFIG_SUNBMAC is not set
# CONFIG_SUNQE is not set
# CONFIG_SUNGEM is not set
# CONFIG_NET_VENDOR_3COM is not set
# CONFIG_LANCE is not set
# CONFIG_NET_VENDOR_SMC is not set
# CONFIG_NET_VENDOR_RACAL is not set
# CONFIG_NET_ISA is not set
# CONFIG_NET_PCI is not set
# CONFIG_NET_POCKET is not set
# CONFIG_CNXT_EMAC is not set
# CONFIG_FEC is not set
# CONFIG_CS89x0 is not set
# CONFIG_UCCS8900 is not set
# CONFIG_AX88796 is not set
# CONFIG_DM9000 is not set

#
# Ethernet (1000 Mbit)
#
# CONFIG_ACENIC is not set
# CONFIG_DL2K is not set
# CONFIG_E1000 is not set
# CONFIG_MYRI_SBUS is not set
# CONFIG_NS83820 is not set
# CONFIG_HAMACHI is not set
# CONFIG_YELLOWFIN is not set
# CONFIG_R8169 is not set
# CONFIG_SK98LIN is not set
# CONFIG_TIGON3 is not set
# CONFIG_FDDI is not set
# CONFIG_HIPPI is not set
# CONFIG_PLIP is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set

#
# Wireless LAN (non-hamradio)
#
# CONFIG_NET_RADIO is not set

#
# Token Ring devices
#
# CONFIG_TR is not set
# CONFIG_NET_FC is not set
# CONFIG_RCPCI is not set
# CONFIG_SHAPER is not set

#
# Wan interfaces
#
# CONFIG_WAN is not set

#
# Amateur Radio support
#
# CONFIG_HAMRADIO is not set

#
# IrDA (infrared) support
#
# CONFIG_IRDA is not set

#
# ATA/IDE/MFM/RLL support
#
# CONFIG_IDE is not set
# CONFIG_BLK_DEV_HD is not set

#
# SCSI support
#
# CONFIG_SCSI is not set

#
# ISDN subsystem
#
# CONFIG_ISDN is not set

#
# Console drivers
#
# CONFIG_VGA_CONSOLE is not set
# CONFIG_FB is not set

#
# Frame-buffer support
#
# CONFIG_FB is not set

#
# Parallel port support
#
# CONFIG_PARPORT is not set

#
# Memory Technology Devices (MTD)
#
CONFIG_MTD=y
# CONFIG_MTD_DEBUG is not set
CONFIG_MTD_PARTITIONS=y
# CONFIG_MTD_CONCAT is not set
# CONFIG_MTD_REDBOOT_PARTS is not set
# CONFIG_MTD_UCBOOTSTRAP_PARTS is not set
CONFIG_MTD_CMDLINE_PARTS=y
# CONFIG_MTD_AFS_PARTS is not set

#
# User Modules And Translation Layers
#
CONFIG_MTD_CHAR=y
CONFIG_MTD_BLOCK=y
# CONFIG_FTL is not set
# CONFIG_NFTL is not set
# CONFIG_INFTL is not set

#
# RAM/ROM/Flash chip drivers
#
CONFIG_MTD_CFI=y
CONFIG_MTD_JEDECPROBE=y
CONFIG_MTD_GEN_PROBE=y
# CONFIG_MTD_CFI_ADV_OPTIONS is not set
CONFIG_MTD_CFI_INTELEXT=y
# CONFIG_MTD_CFI_AMDSTD is not set
# CONFIG_MTD_CFI_STAA is not set
CONFIG_MTD_RAM=y
CONFIG_MTD_ROM=y
# CONFIG_MTD_ABSENT is not set
# CONFIG_MTD_OBSOLETE_CHIPS is not set
# CONFIG_MTD_AMDSTD is not set
# CONFIG_MTD_SHARP is not set
# CONFIG_MTD_JEDEC is not set
# CONFIG_MTD_PSD4256G is not set

#
# Mapping drivers for chip access
#
# CONFIG_MTD_PHYSMAP is not set
# CONFIG_MTD_UCBOOTSTRAP is not set
# CONFIG_MTD_DRAGONIX is not set
# CONFIG_MTD_NETtel is not set
# CONFIG_MTD_SNAPGEODE is not set
# CONFIG_MTD_NETteluC is not set
# CONFIG_MTD_MBVANILLA is not set
# CONFIG_MTD_MB_AUTO is not set
# CONFIG_MTD_ML401 is not set
# CONFIG_MTD_SUZAKU is not set
# CONFIG_MTD_KeyTechnology is not set
# CONFIG_MTD_SED_SIOSIII is not set
# CONFIG_MTD_NORA is not set
# CONFIG_MTD_ARM_INTEGRATOR is not set
# CONFIG_MTD_CDB89712 is not set
# CONFIG_MTD_SA1100 is not set
# CONFIG_MTD_DC21285 is not set
# CONFIG_MTD_IQ80310 is not set
# CONFIG_MTD_EPXA10DB is not set
# CONFIG_MTD_SMART is not set
# CONFIG_MTD_FORTUNET is not set
# CONFIG_MTD_AUTCPU12 is not set
# CONFIG_MTD_IXP425 is not set
# CONFIG_MTD_SE4000 is not set
# CONFIG_MTD_SNAPARM is not set
# CONFIG_MTD_DM270 is not set
# CONFIG_MTD_CLPS7500 is not set
# CONFIG_MTD_EDB7312 is not set
# CONFIG_MTD_EDB9301 is not set
# CONFIG_MTD_EDB9302 is not set
# CONFIG_MTD_EDB9312 is not set
# CONFIG_MTD_EDB9315 is not set
# CONFIG_MTD_IMPA7 is not set
# CONFIG_MTD_CEIVA is not set
CONFIG_MTD_VC547X=y
# CONFIG_MTD_TIBURON is not set
# CONFIG_MTD_EB67DIP is not set
# CONFIG_MTD_UCLINUX is not set
# CONFIG_MTD_PCI is not set
# CONFIG_MTD_PCMCIA is not set

#
# Self-contained MTD device drivers
#
# CONFIG_MTD_PMC551 is not set
# CONFIG_MTD_SLRAM is not set
# CONFIG_MTD_MTDRAM is not set
# CONFIG_MTD_MTDCNXT is not set
# CONFIG_MTD_BLKMTD is not set

#
# Disk-On-Chip Device Drivers
#
# CONFIG_MTD_DOC1000 is not set
# CONFIG_MTD_DOC2000 is not set
# CONFIG_MTD_DOC2001 is not set
# CONFIG_MTD_DOC2001PLUS is not set
# CONFIG_MTD_DOCPROBE is not set

#
# NAND Flash Device Drivers
#
# CONFIG_MTD_NAND is not set

#
# Plug and Play configuration
#
# CONFIG_PNP is not set
# CONFIG_ISAPNP is not set

#
# Block devices
#
# CONFIG_BLK_DEV_FD is not set
# CONFIG_BLK_DEV_XD is not set
# CONFIG_PARIDE is not set
# CONFIG_BLK_CPQ_DA is not set
# CONFIG_BLK_CPQ_CISS_DA is not set
# CONFIG_CISS_SCSI_TAPE is not set
# CONFIG_CISS_MONITOR_THREAD is not set
# CONFIG_BLK_DEV_DAC960 is not set
# CONFIG_BLK_DEV_UMEM is not set
# CONFIG_BLK_DEV_SX8 is not set
CONFIG_BLK_DEV_LOOP=y
# CONFIG_BLK_DEV_NBD is not set
# CONFIG_BLK_DEV_RAM is not set
# CONFIG_BLK_DEV_INITRD is not set
# CONFIG_BLK_DEV_RAMDISK_DATA is not set
# CONFIG_BLK_DEV_BLKMEM is not set
# CONFIG_BLK_STATS is not set

#
# File systems
#
# CONFIG_QUOTA is not set
# CONFIG_QFMT_V2 is not set
# CONFIG_AUTOFS_FS is not set
# CONFIG_AUTOFS4_FS is not set
# CONFIG_REISERFS_FS is not set
# CONFIG_REISERFS_CHECK is not set
# CONFIG_REISERFS_PROC_INFO is not set
# CONFIG_ADFS_FS is not set
# CONFIG_ADFS_FS_RW is not set
# CONFIG_AFFS_FS is not set
# CONFIG_HFS_FS is not set
# CONFIG_HFSPLUS_FS is not set
# CONFIG_BEFS_FS is not set
# CONFIG_BEFS_DEBUG is not set
# CONFIG_BFS_FS is not set
# CONFIG_EXT3_FS is not set
# CONFIG_JBD is not set
# CONFIG_JBD_DEBUG is not set
# CONFIG_FAT_FS is not set
# CONFIG_MSDOS_FS is not set
# CONFIG_UMSDOS_FS is not set
# CONFIG_VFAT_FS is not set
# CONFIG_EFS_FS is not set
# CONFIG_JFFS_FS is not set
CONFIG_JFFS2_FS=y
CONFIG_JFFS2_FS_DEBUG=0
# CONFIG_YAFFS_FS is not set
# CONFIG_CRAMFS is not set
# CONFIG_SQUASHFS is not set
# CONFIG_TMPFS is not set
CONFIG_RAMFS=y
# CONFIG_ISO9660_FS is not set
# CONFIG_JOLIET is not set
# CONFIG_ZISOFS is not set
# CONFIG_JFS_FS is not set
# CONFIG_JFS_DEBUG is not set
# CONFIG_JFS_STATISTICS is not set
# CONFIG_MINIX_FS is not set
# CONFIG_VXFS_FS is not set
# CONFIG_NTFS_FS is not set
# CONFIG_NTFS_RW is not set
# CONFIG_HPFS_FS is not set
CONFIG_PROC_FS=y
CONFIG_PROC_NDYNAMIC=4096
CONFIG_DEVFS_FS=y
CONFIG_DEVFS_MOUNT=y
# CONFIG_DEVFS_DEBUG is not set
# CONFIG_DEVPTS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX4FS_RW is not set
# CONFIG_ROMFS_FS is not set
# CONFIG_EXT2_FS is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UDF_FS is not set
# CONFIG_UDF_RW is not set
# CONFIG_UFS_FS is not set
# CONFIG_UFS_FS_WRITE is not set
# CONFIG_XFS_FS is not set
# CONFIG_XFS_QUOTA is not set
# CONFIG_XFS_RT is not set
# CONFIG_XFS_TRACE is not set
# CONFIG_XFS_DEBUG is not set

#
# Network File Systems
#
# CONFIG_CODA_FS is not set
# CONFIG_INTERMEZZO_FS is not set
CONFIG_NFS_FS=y
CONFIG_NFS_V3=y
# CONFIG_NFS_DIRECTIO is not set
CONFIG_ROOT_NFS=y
# CONFIG_NFSD is not set
# CONFIG_NFSD_V3 is not set
# CONFIG_NFSD_TCP is not set
CONFIG_SUNRPC=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
# CONFIG_SMB_FS is not set
# CONFIG_NCP_FS is not set
# CONFIG_NCPFS_PACKET_SIGNING is not set
# CONFIG_NCPFS_IOCTL_LOCKING is not set
# CONFIG_NCPFS_STRONG is not set
# CONFIG_NCPFS_NFS_NS is not set
# CONFIG_NCPFS_OS2_NS is not set
# CONFIG_NCPFS_SMALLDOS is not set
# CONFIG_NCPFS_NLS is not set
# CONFIG_NCPFS_EXTRAS is not set
# CONFIG_ZISOFS_FS is not set
# CONFIG_COREDUMP_PRINTK is not set

#
# Partition Types
#
# CONFIG_PARTITION_ADVANCED is not set
# CONFIG_SMB_NLS is not set
# CONFIG_NLS is not set

#
# Input core support
#
# CONFIG_INPUT is not set
# CONFIG_INPUT_KEYBDEV is not set
# CONFIG_DUMMY_KEYB is not set
# CONFIG_INPUT_MOUSEDEV is not set
# CONFIG_INPUT_JOYDEV is not set
# CONFIG_INPUT_EVDEV is not set
# CONFIG_INPUT_UINPUT is not set

#
# Character devices
#
CONFIG_SERIAL_C5471=y
CONFIG_SERIAL_C5471_CONSOLE=y
# CONFIG_C5471_WDT is not set
CONFIG_C5471_GIO=m
# CONFIG_LEDMAN is not set
# CONFIG_SNAPDOG is not set
# CONFIG_FAST_TIMER is not set
# CONFIG_DS1302 is not set
# CONFIG_M41T11M6 is not set
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
# CONFIG_SERIAL is not set
# CONFIG_SERIAL_EXTENDED is not set
# CONFIG_SERIAL_NONSTANDARD is not set

#
# Serial drivers
#
# CONFIG_SERIAL_ANAKIN is not set
# CONFIG_SERIAL_ANAKIN_CONSOLE is not set
# CONFIG_SERIAL_AMBA is not set
# CONFIG_SERIAL_AMBA_CONSOLE is not set
# CONFIG_SERIAL_CLPS711X is not set
# CONFIG_SERIAL_CLPS711X_CONSOLE is not set
# CONFIG_SERIAL_21285 is not set
# CONFIG_SERIAL_21285_OLD is not set
# CONFIG_SERIAL_21285_CONSOLE is not set
# CONFIG_SERIAL_UART00 is not set
# CONFIG_SERIAL_UART00_CONSOLE is not set
# CONFIG_SERIAL_SA1100 is not set
# CONFIG_SERIAL_SA1100_CONSOLE is not set
# CONFIG_SERIAL_OMAHA is not set
# CONFIG_SERIAL_OMAHA_CONSOLE is not set
# CONFIG_SERIAL_AT91 is not set
# CONFIG_SERIAL_AT91_CONSOLE is not set
# CONFIG_SERIAL_8250 is not set
# CONFIG_SERIAL_8250_CONSOLE is not set
# CONFIG_SERIAL_8250_EXTENDED is not set
# CONFIG_SERIAL_8250_MANY_PORTS is not set
# CONFIG_SERIAL_8250_SHARE_IRQ is not set
# CONFIG_SERIAL_8250_DETECT_IRQ is not set
# CONFIG_SERIAL_8250_MULTIPORT is not set
# CONFIG_SERIAL_8250_HUB6 is not set
CONFIG_UNIX98_PTYS=y
CONFIG_UNIX98_PTY_COUNT=256

#
# SPI support
#
# CONFIG_SPI is not set

#
# I2C support
#
# CONFIG_I2C is not set

#
# Mice
#
# CONFIG_BUSMOUSE is not set
# CONFIG_MOUSE is not set
# CONFIG_EDB7312_TS is not set

#
# Joysticks
#
# CONFIG_INPUT_GAMEPORT is not set

#
# Input core support is needed for gameports
#

#
# Input core support is needed for joysticks
#
# CONFIG_QIC02_TAPE is not set
# CONFIG_IPMI_HANDLER is not set
# CONFIG_IPMI_PANIC_EVENT is not set
# CONFIG_IPMI_DEVICE_INTERFACE is not set
# CONFIG_IPMI_KCS is not set
# CONFIG_IPMI_WATCHDOG is not set

#
# Controller Area Network Cards/Chips
#
# CONFIG_CAN4LINUX is not set

#
# Watchdog Cards
#
# CONFIG_WATCHDOG is not set
# CONFIG_SCx200 is not set
# CONFIG_SCx200_GPIO is not set
# CONFIG_AMD_PM768 is not set
# CONFIG_NVRAM is not set
# CONFIG_RTC is not set
# CONFIG_DTLK is not set
# CONFIG_R3964 is not set
# CONFIG_APPLICOM is not set

#
# Ftape, the floppy tape device driver
#
# CONFIG_FTAPE is not set
# CONFIG_AGP is not set

#
# Direct Rendering Manager (XFree86 DRI support)
#
# CONFIG_DRM is not set

#
# USB support
#
# CONFIG_USB is not set

#
# Support for USB gadgets
#
# CONFIG_USB_GADGET is not set

#
# IEEE 1394 (FireWire) support (EXPERIMENTAL)
#
# CONFIG_IEEE1394 is not set

#
# I2O device support
#
# CONFIG_I2O is not set
# CONFIG_I2O_BLOCK is not set
# CONFIG_I2O_LAN is not set
# CONFIG_I2O_SCSI is not set
# CONFIG_I2O_PROC is not set

#
# Kernel hacking
#
CONFIG_FRAME_POINTER=y
# CONFIG_REVISIT is not set
CONFIG_DEBUG_ERRORS=y
CONFIG_DEBUG_USER=y
# CONFIG_DEBUG_INFO is not set
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_DEBUG_LL is not set
# CONFIG_CONTIGUOUS_PAGE_ALLOC is not set
# CONFIG_MEM_MAP is not set
# CONFIG_NO_MMU_LARGE_ALLOCS is not set

#
# Cryptographic options
#
# CONFIG_CRYPTO is not set

#
# Library routines
#
# CONFIG_CRC32 is not set
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y

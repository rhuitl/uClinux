#
# Automatically generated make config: don't edit
#
# CONFIG_MMU is not set
CONFIG_UCLINUX=y
# CONFIG_UID16 is not set
CONFIG_RWSEM_GENERIC_SPINLOCK=y
# CONFIG_RWSEM_XCHGADD_ALGORITHM is not set
# CONFIG_ISA is not set
# CONFIG_ISAPNP is not set
# CONFIG_EISA is not set
# CONFIG_MCA is not set

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y

#
# Loadable module support
#
# CONFIG_MODULES is not set
CONFIG_V850=y

#
# Processor type and features
#
# CONFIG_V850E_SIM is not set
# CONFIG_RTE_CB_MA1 is not set
CONFIG_RTE_CB_NB85E=y
# CONFIG_RTE_CB_ME2 is not set
# CONFIG_V850E_AS85EP1 is not set
# CONFIG_V850E2_SIM85E2C is not set
# CONFIG_V850E2_SIM85E2S is not set
# CONFIG_V850E2_FPGA85E2C is not set
# CONFIG_V850E2_ANNA is not set
CONFIG_V850E=y
# CONFIG_V850E_MA1 is not set
CONFIG_V850E_TEG=y
# CONFIG_V850E_ME2 is not set
CONFIG_V850E_UART=y
# CONFIG_V850E_UARTB is not set
CONFIG_V850E_UART_CONSOLE=y
# CONFIG_V850E2_SIM85E2 is not set
# CONFIG_V850E2 is not set
CONFIG_RTE_CB=y
CONFIG_RTE_CB_MULTI=y
CONFIG_RTE_CB_MULTI_DBTRAP=y
# CONFIG_RTE_CB_MA1_KSRAM is not set
CONFIG_RTE_MB_A_PCI=y
CONFIG_RTE_GBUS_INT=y
CONFIG_PCI=y
CONFIG_V850E_INTC=y
CONFIG_V850E_TIMER_D=y
CONFIG_V850E_CACHE=y
# CONFIG_V850E2_CACHE is not set
# CONFIG_NO_CACHE is not set
# CONFIG_V850E_HIGHRES_TIMER is not set
# CONFIG_TIME_BOOTUP is not set
# CONFIG_RESET_GUARD is not set
CONFIG_ZERO_BSS=y

#
# General setup
#
CONFIG_NET=y
# CONFIG_DISK is not set
# CONFIG_PCI_NAMES is not set
# CONFIG_HOTPLUG is not set
# CONFIG_PCMCIA is not set
# CONFIG_SYSVIPC is not set
# CONFIG_BSD_PROCESS_ACCT is not set
# CONFIG_SYSCTL is not set
CONFIG_KCORE_ELF=y
# CONFIG_KCORE_AOUT is not set
CONFIG_BINFMT_FLAT=y
# CONFIG_BINFMT_ZFLAT is not set
# CONFIG_BINFMT_MISC is not set
CONFIG_CONTIGUOUS_PAGE_ALLOC=y
CONFIG_MEM_MAP=y

#
# Parallel port support
#
# CONFIG_PARPORT is not set

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
# CONFIG_BLK_DEV_LOOP is not set
# CONFIG_BLK_DEV_NBD is not set
# CONFIG_BLK_DEV_RAM is not set
# CONFIG_BLK_DEV_INITRD is not set
# CONFIG_BLK_DEV_RAMDISK_DATA is not set
CONFIG_BLK_DEV_BLKMEM=y
CONFIG_NOFLASH=y
# CONFIG_AMDFLASH is not set
# CONFIG_INTELFLASH is not set
# CONFIG_BLK_STATS is not set

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
# CONFIG_IP_MULTICAST is not set
# CONFIG_IP_ADVANCED_ROUTER is not set
# CONFIG_IP_PNP is not set
# CONFIG_NET_ARP_LIMIT is not set
# CONFIG_NET_IPIP is not set
# CONFIG_NET_IPGRE is not set
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
# IEEE 1394 (FireWire) support (EXPERIMENTAL)
#
# CONFIG_IEEE1394 is not set

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
# CONFIG_SUNLANCE is not set
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNBMAC is not set
# CONFIG_SUNQE is not set
# CONFIG_SUNGEM is not set
# CONFIG_NET_VENDOR_3COM is not set
# CONFIG_LANCE is not set
# CONFIG_NET_VENDOR_SMC is not set
# CONFIG_NET_VENDOR_RACAL is not set
# CONFIG_HP100 is not set
# CONFIG_NET_ISA is not set
CONFIG_NET_PCI=y
# CONFIG_PCNET32 is not set
# CONFIG_PCNET32_VMWARE is not set
# CONFIG_AMD8111_ETH is not set
# CONFIG_ADAPTEC_STARFIRE is not set
# CONFIG_APRICOT is not set
# CONFIG_B44 is not set
# CONFIG_CS89x0 is not set
# CONFIG_TULIP is not set
# CONFIG_DE4X5 is not set
# CONFIG_DGRS is not set
# CONFIG_DM9102 is not set
# CONFIG_EEPRO100 is not set
# CONFIG_EEPRO100_PIO is not set
CONFIG_E100=y
# CONFIG_LNE390 is not set
# CONFIG_FEALNX is not set
# CONFIG_NATSEMI is not set
# CONFIG_NE2K_PCI is not set
# CONFIG_FORCEDETH is not set
# CONFIG_NE3210 is not set
# CONFIG_ES3210 is not set
# CONFIG_8139CP is not set
# CONFIG_8139TOO is not set
# CONFIG_8139TOO_PIO is not set
# CONFIG_8139TOO_TUNE_TWISTER is not set
# CONFIG_8139TOO_8129 is not set
# CONFIG_8139_OLD_RX_RESET is not set
# CONFIG_8139TOO_EXTERNAL_PHY is not set
# CONFIG_RTL8139 is not set
# CONFIG_SIS900 is not set
# CONFIG_EPIC100 is not set
# CONFIG_SUNDANCE is not set
# CONFIG_SUNDANCE_MMIO is not set
# CONFIG_TLAN is not set
# CONFIG_VIA_RHINE is not set
# CONFIG_VIA_RHINE_FET is not set
# CONFIG_VIA_RHINE_MMIO is not set
# CONFIG_WINBOND_840 is not set
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
# ISDN subsystem
#
# CONFIG_ISDN is not set

#
# Character devices
#
# CONFIG_LEDMAN is not set
# CONFIG_SNAPDOG is not set
# CONFIG_FAST_TIMER is not set
# CONFIG_DS1302 is not set
# CONFIG_M41T11M6 is not set
# CONFIG_VT is not set
# CONFIG_SERIAL is not set
# CONFIG_SERIAL_EXTENDED is not set
# CONFIG_SERIAL_NONSTANDARD is not set

#
# Serial drivers
#
# CONFIG_SERIAL_8250 is not set
# CONFIG_SERIAL_8250_CONSOLE is not set
# CONFIG_SERIAL_8250_EXTENDED is not set
# CONFIG_SERIAL_8250_MANY_PORTS is not set
# CONFIG_SERIAL_8250_SHARE_IRQ is not set
# CONFIG_SERIAL_8250_DETECT_IRQ is not set
# CONFIG_SERIAL_8250_MULTIPORT is not set
# CONFIG_SERIAL_8250_HUB6 is not set
# CONFIG_UNIX98_PTYS is not set

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
# CONFIG_INPUT_NS558 is not set
# CONFIG_INPUT_LIGHTNING is not set
# CONFIG_INPUT_PCIGAME is not set
# CONFIG_INPUT_CS461X is not set
# CONFIG_INPUT_EMU10K1 is not set
# CONFIG_INPUT_SERIO is not set
# CONFIG_INPUT_SERPORT is not set

#
# Joysticks
#
# CONFIG_INPUT_ANALOG is not set
# CONFIG_INPUT_A3D is not set
# CONFIG_INPUT_ADI is not set
# CONFIG_INPUT_COBRA is not set
# CONFIG_INPUT_GF2K is not set
# CONFIG_INPUT_GRIP is not set
# CONFIG_INPUT_INTERACT is not set
# CONFIG_INPUT_TMDC is not set
# CONFIG_INPUT_SIDEWINDER is not set
# CONFIG_INPUT_IFORCE_USB is not set
# CONFIG_INPUT_IFORCE_232 is not set
# CONFIG_INPUT_WARRIOR is not set
# CONFIG_INPUT_MAGELLAN is not set
# CONFIG_INPUT_SPACEORB is not set
# CONFIG_INPUT_SPACEBALL is not set
# CONFIG_INPUT_STINGER is not set
# CONFIG_INPUT_DB9 is not set
# CONFIG_INPUT_GAMECON is not set
# CONFIG_INPUT_TURBOGRAFX is not set
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
# CONFIG_JFFS2_FS is not set
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
# CONFIG_DEVFS_FS is not set
# CONFIG_DEVFS_MOUNT is not set
# CONFIG_DEVFS_DEBUG is not set
# CONFIG_DEVPTS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX4FS_RW is not set
CONFIG_ROMFS_FS=y
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
# CONFIG_ROOT_NFS is not set
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
# Sound
#
# CONFIG_SOUND is not set

#
# USB support
#
# CONFIG_USB is not set

#
# Support for USB gadgets
#
# CONFIG_USB_GADGET is not set

#
# Kernel hacking
#
CONFIG_FULLDEBUG=y
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_PROFILE is not set
# CONFIG_NO_KERNEL_MSG is not set

#
# Cryptographic options
#
# CONFIG_CRYPTO is not set

#
# Library routines
#
# CONFIG_CRC32 is not set
# CONFIG_ZLIB_INFLATE is not set
# CONFIG_ZLIB_DEFLATE is not set

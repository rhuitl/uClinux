#
# Automatically generated make config: don't edit
#
CONFIG_SUPERH=y
CONFIG_UID16=y
CONFIG_RWSEM_GENERIC_SPINLOCK=y
# CONFIG_RWSEM_XCHGADD_ALGORITHM is not set

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y

#
# Loadable module support
#
CONFIG_MODULES=y
# CONFIG_MODVERSIONS is not set
# CONFIG_KMOD is not set

#
# Processor type and features
#
# CONFIG_SH_GENERIC is not set
# CONFIG_SH_SH4202_MICRODEV is not set
# CONFIG_SH_SOLUTION_ENGINE is not set
# CONFIG_SH_7751_SOLUTION_ENGINE is not set
# CONFIG_SH_MOBILE_SOLUTION_ENGINE is not set
# CONFIG_SH_STB1_HARP is not set
# CONFIG_SH_STB1_OVERDRIVE is not set
# CONFIG_SH_HP620 is not set
# CONFIG_SH_HP680 is not set
# CONFIG_SH_HP690 is not set
# CONFIG_SH_CQREEK is not set
# CONFIG_SH_DMIDA is not set
# CONFIG_SH_EC3104 is not set
# CONFIG_SH_DREAMCAST is not set
# CONFIG_SH_CAT68701 is not set
# CONFIG_SH_BIGSUR is not set
# CONFIG_SH_SH2000 is not set
# CONFIG_SH_HS7729PCI is not set
# CONFIG_SH_ADX is not set
# CONFIG_SH_SECUREEDGE5410 is not set
CONFIG_SH_KEYWEST=y
# CONFIG_SH_UNKNOWN is not set
CONFIG_SH_RTC=y
# CONFIG_CPU_SUBTYPE_SH7300 is not set
# CONFIG_CPU_SUBTYPE_SH7707 is not set
# CONFIG_CPU_SUBTYPE_SH7708 is not set
CONFIG_CPU_SUBTYPE_SH7709=y
# CONFIG_CPU_SUBTYPE_SH7750 is not set
# CONFIG_CPU_SUBTYPE_SH7751R is not set
# CONFIG_CPU_SUBTYPE_SH7751 is not set
# CONFIG_CPU_SUBTYPE_SH4_202 is not set
# CONFIG_CPU_SUBTYPE_ST40STB1 is not set
# CONFIG_CPU_SUBTYPE_ST40GX1 is not set
CONFIG_CPU_SH3=y
# CONFIG_CPU_SH4 is not set
CONFIG_CPU_LITTLE_ENDIAN=y
CONFIG_MEMORY_START=0c000000
CONFIG_MEMORY_SIZE=00400000
CONFIG_MEMORY_SET=y
CONFIG_SH_SNAPGEAR=y
CONFIG_BOOT_LINK_OFFSET=0x00210000
# CONFIG_SCRATCH_SPACE is not set
CONFIG_SH_DSP=y
# CONFIG_DISCONTIGMEM is not set

#
# General setup
#
CONFIG_ISA=y
# CONFIG_EISA is not set
# CONFIG_MCA is not set
# CONFIG_SBUS is not set
CONFIG_NET=y
# CONFIG_HD64461 is not set
CONFIG_HD64465=y
CONFIG_HD64465_IOBASE=0xb0000000
CONFIG_HD64465_IRQ=33
# CONFIG_UBC_WAKEUP is not set
# CONFIG_SH_DMA is not set
CONFIG_SH_PCLK_FREQ=0
# CONFIG_CMDLINE_BOOL is not set
CONFIG_PCI=y
# CONFIG_PCI_SD0001 is not set
CONFIG_SH_PCIDMA_NONCOHERENT=y
CONFIG_PCI_NAMES=y
CONFIG_HOTPLUG=y

#
# PCMCIA/CardBus support
#
CONFIG_PCMCIA=y
# CONFIG_CARDBUS is not set
# CONFIG_TCIC is not set
CONFIG_HD64465_PCMCIA=y
# CONFIG_I82092 is not set
# CONFIG_I82365 is not set
CONFIG_SYSVIPC=y
# CONFIG_BSD_PROCESS_ACCT is not set
CONFIG_SYSCTL=y
CONFIG_KCORE_ELF=y
# CONFIG_KCORE_AOUT is not set
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_MISC=y
# CONFIG_OOM_KILLER is not set

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
# CONFIG_MTD_CMDLINE_PARTS is not set

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
# CONFIG_MTD_JEDECPROBE is not set
CONFIG_MTD_GEN_PROBE=y
# CONFIG_MTD_CFI_ADV_OPTIONS is not set
CONFIG_MTD_CFI_INTELEXT=y
# CONFIG_MTD_CFI_AMDSTD is not set
# CONFIG_MTD_CFI_STAA is not set
# CONFIG_MTD_RAM is not set
# CONFIG_MTD_ROM is not set
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
# CONFIG_MTD_SOLUTIONENGINE is not set
CONFIG_MTD_KEYWEST=y
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
CONFIG_BLK_DEV_NBD=y
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_SIZE=8192
CONFIG_BLK_DEV_INITRD=y
# CONFIG_BLK_DEV_RAMDISK_DATA is not set
# CONFIG_BLK_DEV_BLKMEM is not set
# CONFIG_BLK_STATS is not set

#
# Multi-device support (RAID and LVM)
#
# CONFIG_MD is not set
# CONFIG_BLK_DEV_MD is not set
# CONFIG_MD_LINEAR is not set
# CONFIG_MD_RAID0 is not set
# CONFIG_MD_RAID1 is not set
# CONFIG_MD_RAID5 is not set
# CONFIG_MD_MULTIPATH is not set
# CONFIG_BLK_DEV_LVM is not set

#
# Networking options
#
CONFIG_PACKET=y
# CONFIG_PACKET_MMAP is not set
# CONFIG_NETLINK_DEV is not set
CONFIG_NETFILTER=y
CONFIG_NETFILTER_DEBUG=y
CONFIG_FILTER=y
# CONFIG_NET_NEIGH_DEBUG is not set
# CONFIG_NET_RESTRICTED_REUSE is not set
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
# CONFIG_IP_MULTIPLE_TABLES is not set
# CONFIG_IP_ROUTE_BIG_RT_CACHE is not set
# CONFIG_IP_ROUTE_MULTIPATH is not set
# CONFIG_IP_ROUTE_MULTIPATH_SEQUENTIAL is not set
# CONFIG_IP_ROUTE_TOS is not set
# CONFIG_IP_ROUTE_VERBOSE is not set
# CONFIG_IP_PNP is not set
# CONFIG_NET_ARP_LIMIT is not set
# CONFIG_NET_IPIP is not set
# CONFIG_NET_IPGRE is not set
# CONFIG_IP_MROUTE is not set
# CONFIG_ARPD is not set
# CONFIG_INET_ECN is not set
CONFIG_SYN_COOKIES=y

#
#   IP: Netfilter Configuration
#
CONFIG_IP_NF_CONNTRACK=y
CONFIG_IP_NF_FTP=y
# CONFIG_IP_NF_CONNTRACK_MARK is not set
# CONFIG_IP_NF_H323 is not set
# CONFIG_IP_NF_AMANDA is not set
# CONFIG_IP_NF_TFTP is not set
CONFIG_IP_NF_IRC=y
# CONFIG_IP_NF_CT_PROTO_GRE is not set
# CONFIG_IP_NF_PPTP is not set
# CONFIG_IP_NF_CT_ACCT is not set
# CONFIG_IP_NF_CT_DEV is not set
# CONFIG_IP_NF_CONNTRACK_EVENTS is not set
# CONFIG_IP_NF_QUEUE is not set
CONFIG_IP_NF_IPTABLES=y
# CONFIG_IP_NF_MATCH_LIMIT is not set
# CONFIG_IP_NF_MATCH_IPRANGE is not set
CONFIG_IP_NF_MATCH_MAC=y
# CONFIG_IP_NF_MATCH_PKTTYPE is not set
CONFIG_IP_NF_MATCH_MARK=y
CONFIG_IP_NF_MATCH_MULTIPORT=y
CONFIG_IP_NF_MATCH_TOS=y
# CONFIG_IP_NF_MATCH_TIME is not set
# CONFIG_IP_NF_MATCH_RECENT is not set
# CONFIG_IP_NF_MATCH_ECN is not set
# CONFIG_IP_NF_MATCH_DSCP is not set
# CONFIG_IP_NF_MATCH_AH_ESP is not set
CONFIG_IP_NF_MATCH_LENGTH=y
CONFIG_IP_NF_MATCH_TTL=y
CONFIG_IP_NF_MATCH_TCPMSS=y
# CONFIG_IP_NF_MATCH_HELPER is not set
CONFIG_IP_NF_MATCH_STATE=y
# CONFIG_IP_NF_MATCH_CONNTRACK is not set
CONFIG_IP_NF_MATCH_UNCLEAN=y
# CONFIG_IP_NF_MATCH_STRING is not set
CONFIG_IP_NF_MATCH_OWNER=y
# CONFIG_IP_NF_MATCH_LAYER7 is not set
# CONFIG_IP_NF_MATCH_LAYER7_DEBUG is not set
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_TARGET_REJECT=y
CONFIG_IP_NF_TARGET_MIRROR=y
# CONFIG_IP_NF_BIG_CONNTRACK is not set
CONFIG_IP_NF_NAT=y
CONFIG_IP_NF_NAT_NEEDED=y
CONFIG_IP_NF_TARGET_MASQUERADE=y
CONFIG_IP_NF_TARGET_REDIRECT=y
# CONFIG_IP_NF_TARGET_NETMAP is not set
# CONFIG_IP_NF_NAT_SNMP_BASIC is not set
CONFIG_IP_NF_NAT_IRC=y
CONFIG_IP_NF_NAT_FTP=y
CONFIG_IP_NF_MANGLE=y
CONFIG_IP_NF_TARGET_TOS=y
# CONFIG_IP_NF_TARGET_ECN is not set
# CONFIG_IP_NF_TARGET_DSCP is not set
CONFIG_IP_NF_TARGET_MARK=y
# CONFIG_IP_NF_TARGET_IMQ is not set
CONFIG_IP_NF_TARGET_LOG=y
# CONFIG_IP_NF_TARGET_CONNLOG is not set
# CONFIG_IP_NF_TARGET_ULOG is not set
CONFIG_IP_NF_TARGET_TCPMSS=y
# CONFIG_IP_NF_TARGET_LED is not set
# CONFIG_IP_NF_ARPTABLES is not set

#
#   IP: Virtual Server Configuration
#
# CONFIG_IP_VS is not set
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
CONFIG_IPSEC=y

#
# FreeSWAN
#

#
# IPSec options (FreeS/WAN)
#
CONFIG_IPSEC_IPIP=y
CONFIG_IPSEC_ALG=y
CONFIG_IPSEC_ALG_AES=y
CONFIG_IPSEC_AH=y
CONFIG_IPSEC_AUTH_HMAC_MD5=y
CONFIG_IPSEC_AUTH_HMAC_SHA1=y
CONFIG_IPSEC_ESP=y
CONFIG_IPSEC_ENC_DES=y
CONFIG_IPSEC_ENC_3DES=y
CONFIG_IPSEC_IPCOMP=y
# CONFIG_IPSEC_IPCOMP_LZS is not set
# CONFIG_IXP4XX_CRYPTO is not set
CONFIG_IPSEC_DEBUG=y
# CONFIG_KLIPS is not set

#
# Network testing
#
# CONFIG_NET_PKTGEN is not set
# CONFIG_IPSEC_NAT_TRAVERSAL is not set

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
# CONFIG_IMQ is not set
# CONFIG_TUN is not set
# CONFIG_ETHERTAP is not set

#
# Ethernet (10 or 100Mbit)
#
CONFIG_NET_ETHERNET=y
# CONFIG_STNIC is not set
# CONFIG_SUNLANCE is not set
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNBMAC is not set
# CONFIG_SUNQE is not set
# CONFIG_SUNGEM is not set
# CONFIG_NET_VENDOR_3COM is not set
# CONFIG_LANCE is not set
CONFIG_NET_VENDOR_SMC=y
# CONFIG_WD80x3 is not set
# CONFIG_ULTRAMCA is not set
# CONFIG_ULTRA is not set
# CONFIG_ULTRA32 is not set
CONFIG_SMC9194=m
# CONFIG_SMC91111 is not set
# CONFIG_NET_VENDOR_RACAL is not set
# CONFIG_AT1700 is not set
# CONFIG_DEPCA is not set
# CONFIG_HP100 is not set
# CONFIG_NET_ISA is not set
CONFIG_NET_PCI=y
# CONFIG_PCNET32 is not set
# CONFIG_PCNET32_VMWARE is not set
# CONFIG_AMD8111_ETH is not set
# CONFIG_ADAPTEC_STARFIRE is not set
# CONFIG_AC3200 is not set
# CONFIG_APRICOT is not set
# CONFIG_B44 is not set
# CONFIG_CS89x0 is not set
CONFIG_TULIP=m
# CONFIG_TULIP_MWI is not set
# CONFIG_TULIP_MMIO is not set
# CONFIG_DE4X5 is not set
# CONFIG_DGRS is not set
# CONFIG_DM9102 is not set
# CONFIG_EEPRO100 is not set
# CONFIG_EEPRO100_PIO is not set
# CONFIG_E100 is not set
# CONFIG_LNE390 is not set
# CONFIG_FEALNX is not set
# CONFIG_NATSEMI is not set
CONFIG_NE2K_PCI=m
# CONFIG_FORCEDETH is not set
# CONFIG_NE3210 is not set
# CONFIG_ES3210 is not set
# CONFIG_8139CP is not set
CONFIG_8139TOO=m
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
CONFIG_PPP=y
# CONFIG_PPP_MULTILINK is not set
# CONFIG_PPP_FILTER is not set
CONFIG_PPP_ASYNC=y
# CONFIG_PPP_SYNC_TTY is not set
CONFIG_PPP_DEFLATE=y
CONFIG_PPP_BSDCOMP=y
# CONFIG_PPP_MPPE is not set
# CONFIG_PPPOE is not set
CONFIG_SLIP=y
CONFIG_SLIP_COMPRESSED=y
# CONFIG_SLIP_SMART is not set
# CONFIG_SLIP_MODE_SLIP6 is not set

#
# Wireless LAN (non-hamradio)
#
CONFIG_NET_RADIO=y
# CONFIG_STRIP is not set
# CONFIG_WAVELAN is not set
# CONFIG_ARLAN is not set
# CONFIG_AIRONET4500 is not set
# CONFIG_AIRONET4500_NONCS is not set
# CONFIG_AIRONET4500_PROC is not set
# CONFIG_AIRO is not set
CONFIG_HERMES=m
# CONFIG_PLX_HERMES is not set
# CONFIG_TMD_HERMES is not set
# CONFIG_PCI_HERMES is not set

#
# Wireless Pcmcia cards support
#
CONFIG_PCMCIA_HERMES=m
CONFIG_AIRO_CS=m
# CONFIG_PCMCIA_ATMEL is not set

#
# Prism54 PCI/PCMCIA GT/Duette Driver - 802.11(a/b/g)
#
# CONFIG_PRISM54 is not set
CONFIG_NET_WIRELESS=y

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
# PCMCIA network device support
#
CONFIG_NET_PCMCIA=y
CONFIG_PCMCIA_3C589=m
CONFIG_PCMCIA_3C574=m
CONFIG_PCMCIA_FMVJ18X=m
CONFIG_PCMCIA_PCNET=m
# CONFIG_PCMCIA_AXNET is not set
CONFIG_PCMCIA_NMCLAN=m
CONFIG_PCMCIA_SMC91C92=m
CONFIG_PCMCIA_XIRC2PS=m
# CONFIG_ARCNET_COM20020_CS is not set
# CONFIG_PCMCIA_IBMTR is not set
CONFIG_NET_PCMCIA_RADIO=y
CONFIG_PCMCIA_RAYCS=m
CONFIG_PCMCIA_NETWAVE=m
CONFIG_PCMCIA_WAVELAN=m
# CONFIG_AIRONET4500_CS is not set

#
# Old CD-ROM drivers (not SCSI, not IDE)
#
# CONFIG_CD_NO_IDESCSI is not set

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
# CONFIG_VT is not set
CONFIG_SERIAL=m
CONFIG_SH_SCI=y
CONFIG_SERIAL_CONSOLE=y

#
# Unix 98 PTY support
#
# CONFIG_UNIX98_PTYS is not set

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
# CONFIG_PSMOUSE is not set

#
# Watchdog Cards
#
# CONFIG_WATCHDOG is not set
# CONFIG_RTC is not set

#
# PCMCIA character devices
#
# CONFIG_PCMCIA_SERIAL_CS is not set
# CONFIG_SYNCLINK_CS is not set
CONFIG_LEDMAN=y
# CONFIG_SNAPDOG is not set
# CONFIG_FAST_TIMER is not set
CONFIG_XYMEM=y

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
CONFIG_EXT3_FS=y
CONFIG_JBD=y
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
CONFIG_MINIX_FS=y
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
CONFIG_EXT2_FS=y
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
CONFIG_NFSD=y
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
# Multimedia devices
#
# CONFIG_VIDEO_DEV is not set

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
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_SH_STANDARD_BIOS is not set
# CONFIG_COMMAND_LINE is not set
# CONFIG_SH_KGDB is not set
CONFIG_LOG_BUF_SHIFT=0

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
# CONFIG_FW_LOADER is not set

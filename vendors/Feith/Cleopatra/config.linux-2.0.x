#
# Automatically generated make config: don't edit
#
CONFIG_UCLINUX=y

#
# Code maturity level options
#
CONFIG_EXPERIMENTAL=y

#
# Loadable module support
#
# CONFIG_MODULES is not set

#
# Platform dependant setup
#
# CONFIG_M68000 is not set
# CONFIG_M68EN302 is not set
# CONFIG_M68328 is not set
# CONFIG_M68EZ328 is not set
# CONFIG_M68332 is not set
# CONFIG_M68360 is not set
# CONFIG_M68376 is not set
# CONFIG_M5204 is not set
# CONFIG_M5206 is not set
# CONFIG_M5206e is not set
# CONFIG_M5249 is not set
# CONFIG_M5272 is not set
CONFIG_M5307=y
# CONFIG_M5407 is not set
CONFIG_COLDFIRE=y
# CONFIG_CLOCK_AUTO is not set
# CONFIG_CLOCK_11MHz is not set
# CONFIG_CLOCK_16MHz is not set
# CONFIG_CLOCK_20MHz is not set
# CONFIG_CLOCK_24MHz is not set
# CONFIG_CLOCK_25MHz is not set
# CONFIG_CLOCK_33MHz is not set
# CONFIG_CLOCK_40MHz is not set
CONFIG_CLOCK_45MHz=y
# CONFIG_CLOCK_48MHz is not set
# CONFIG_CLOCK_50MHz is not set
# CONFIG_CLOCK_54MHz is not set
# CONFIG_CLOCK_60MHz is not set
# CONFIG_CLOCK_64MHz is not set
# CONFIG_CLOCK_66MHz is not set
# CONFIG_CLOCK_70MHz is not set
# CONFIG_CLOCK_140MHz is not set
# CONFIG_OLDMASK is not set

#
# Platform
#
# CONFIG_ARN5307 is not set
# CONFIG_M5307C3 is not set
# CONFIG_eLIA is not set
# CONFIG_DISKtel is not set
# CONFIG_SECUREEDGEMP3 is not set
CONFIG_CLEOPATRA=y
# CONFIG_NETtel is not set
# CONFIG_SNAPGEAR is not set
# CONFIG_ROMFS_FROM_ROM is not set
CONFIG_HW_FEITH=y
# CONFIG_RAMAUTO is not set
# CONFIG_RAM05MB is not set
# CONFIG_RAM1MB is not set
# CONFIG_RAM2MB is not set
# CONFIG_RAM4MB is not set
# CONFIG_RAM8MB is not set
CONFIG_RAM16MB=y
# CONFIG_RAM32MB is not set
# CONFIG_RAM64MB is not set
CONFIG_AUTOBIT=y
# CONFIG_RAM8BIT is not set
# CONFIG_RAM16BIT is not set
# CONFIG_RAM32bit is not set
CONFIG_RAMKERNEL=y
# CONFIG_ROMKERNEL is not set

#
# General setup
#
# CONFIG_PCI is not set
CONFIG_NET=y
# CONFIG_SYSVIPC is not set
CONFIG_REDUCED_MEMORY=y
CONFIG_BINFMT_FLAT=y
# CONFIG_BINFMT_ZFLAT is not set
CONFIG_KERNEL_ELF=y
# CONFIG_CONSOLE is not set

#
# Floppy, IDE, and other block devices
#
CONFIG_BLK_DEV_BLKMEM=y
# CONFIG_NOFLASH is not set
CONFIG_AMDFLASH=y
# CONFIG_INTELFLASH is not set
# CONFIG_FLASHAUTO is not set
# CONFIG_FLASH128KB is not set
# CONFIG_FLASH512KB is not set
# CONFIG_FLASH1MB is not set
# CONFIG_FLASH2MB is not set
CONFIG_FLASH4MB=y
# CONFIG_FLASH6MB is not set
# CONFIG_FLASH8MB is not set
# CONFIG_FLASH16MB is not set
# CONFIG_FLASHAUTOBIT is not set
# CONFIG_FLASH8BIT is not set
CONFIG_FLASH16BIT=y
# CONFIG_FLASH32bit is not set
# CONFIG_FLASH_SNAPGEAR is not set
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
# CONFIG_BLK_DEV_NFA is not set

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
CONFIG_PPP=y

#
# CCP compressors for PPP are only built as modules.
#
# CONFIG_EQUALIZER is not set
# CONFIG_UCCS8900 is not set
CONFIG_SMC9194=y
# CONFIG_SMC91111 is not set
# CONFIG_NE2000 is not set
# CONFIG_FEC is not set

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
CONFIG_SMB_FS=y
# CONFIG_SMB_WIN95 is not set
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
CONFIG_COLDFIRE_SERIAL=y
# CONFIG_SERIAL is not set
# CONFIG_MCF_MBUS is not set
# CONFIG_MCF_QSPI is not set
# CONFIG_LCDTXT is not set
# CONFIG_KEYPAD is not set
# CONFIG_KEY is not set
# CONFIG_LCDDMA is not set
# CONFIG_DAC0800 is not set
# CONFIG_DACI2S is not set
# CONFIG_T6963 is not set
# CONFIG_LEDMAN is not set
# CONFIG_LIRC_INTR is not set
# CONFIG_IDETEST is not set
# CONFIG_RESETSWITCH is not set
# CONFIG_DS1302 is not set
# CONFIG_EXP is not set
# CONFIG_WATCHDOG is not set
# CONFIG_DS1743 is not set

#
# Sound support
#
# CONFIG_M5249AUDIO is not set
# CONFIG_AD1845 is not set

#
# Kernel hacking
#
# CONFIG_FULLDEBUG is not set
CONFIG_ALLOC2=y
# CONFIG_PROFILE is not set
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_DUMPTOFLASH is not set
# CONFIG_MEMORY_PROTECT is not set
# CONFIG_BDM_DISABLE is not set

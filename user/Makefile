#
#	Makefile -- Build instructions for user level apps
#

.EXPORT_ALL_VARIABLES:
.PHONY: all romfs clean prune

#
# Include architecture specific build rules.
#

_reldir = .
include user.mak

#
# must run the vendor build first
#
dir_v = $(PRODUCTDIR)
dir_p = $(ROOTDIR)/prop

dir_y = 
dir_n =
dir_  =

dir_$(CONFIG_JFFS_FS)                       += mtd-utils
dir_$(CONFIG_JFFS2_FS)                      += mtd-utils

dir_$(CONFIG_USER_AGETTY_AGETTY)            += agetty
dir_$(CONFIG_USER_APPWEB_APPWEB)            += appWeb
dir_$(CONFIG_USER_ARJ_ARJ)                  += arj
dir_$(CONFIG_USER_ASTERISK)                 += asterisk
dir_$(CONFIG_USER_ASTERISK_MYSQL)           += asterisk-addons
dir_$(CONFIG_USER_AT_AT)                    += at
dir_$(CONFIG_USER_AT_ATD)                   += at
dir_$(CONFIG_USER_AT_ATRUN)                 += at
dir_$(CONFIG_USER_BASH_BASH)                += bash
dir_$(CONFIG_USER_BIND_BIND)                += bind
dir_$(CONFIG_USER_BOA_SRC_BOA)              += boa
dir_$(CONFIG_USER_BOOTTOOLS_LOADER)         += boottools
dir_$(CONFIG_USER_BOOTTOOLS_HIMEMLOADER)    += boottools
dir_$(CONFIG_USER_BOOTTOOLS_PRINTBENV)      += boottools
dir_$(CONFIG_USER_BOOTTOOLS_SETBENV)        += boottools
dir_$(CONFIG_USER_BOOTTOOLS_RESET)          += boottools
dir_$(CONFIG_USER_BOOTTOOLS_MD5SUM)         += boottools
dir_$(CONFIG_USER_BPALOGIN_BPALOGIN)        += bpalogin
dir_$(CONFIG_USER_BR2684CTL_BR2684CTL)      += br2684ctl
dir_$(CONFIG_USER_BRCFG_BRCFG)              += brcfg
dir_$(CONFIG_USER_BRCTL_BRCTL)              += bridge-utils
dir_$(CONFIG_USER_BUSYBOX_BUSYBOX)          += busybox
dir_$(CONFIG_USER_CAL_CAL)                  += cal
dir_$(CONFIG_USER_CAL_DATE)                 += cal
dir_$(CONFIG_USER_CAMSERV)                  += camserv
dir_$(CONFIG_USER_CAN_EXAMPLES)             += can4linux
dir_$(CONFIG_USER_CTORRENT_CTORRENT)        += ctorrent
dir_$(CONFIG_USER_CAN_HORCH)                += horch
dir_$(CONFIG_USER_CGI_GENERIC)              += cgi_generic
dir_$(CONFIG_USER_CGIHTML)                  += cgihtml/examples
dir_$(CONFIG_USER_CHAT_CHAT)                += pppd
dir_$(CONFIG_USER_CKSUM_CKSUM)              += cksum
dir_$(CONFIG_USER_CLAMAV_CLAMAV)            += clamav
dir_$(CONFIG_USER_CLAMAV_CLAMSMTP)          += clamsmtp
dir_$(CONFIG_USER_CLOCK_CLOCK)              += clock
dir_$(CONFIG_USER_CONNTRACK_CONNTRACK)      += conntrack-tools
dir_$(CONFIG_USER_CPU_CPU)                  += cpu
dir_$(CONFIG_USER_CRAMFS_MKCRAMFS)          += cramfs
dir_$(CONFIG_USER_CRAMFS_CRAMFSCK)          += cramfs
dir_$(CONFIG_USER_CRON_CRON)                += cron
dir_$(CONFIG_USER_CRYPTO_TOOLS_CRYPTOTEST)  += crypto-tools
dir_$(CONFIG_USER_CRYPTO_TOOLS_CRYPTOKEYTEST)  += crypto-tools
dir_$(CONFIG_USER_CXXTEST_CXXTEST)          += cxxtest
dir_$(CONFIG_USER_DDNS3_CLIENT_DDNS3)        += ddns3-client
dir_$(CONFIG_USER_DE2TSCAL_DE2TSCAL)        += de2ts-cal
dir_$(CONFIG_USER_DEBUG_DEBUG)		    += debug
dir_$(CONFIG_USER_DEMO_BUTTON)              += demo
dir_$(CONFIG_USER_DEMO_MORSE)               += demo
dir_$(CONFIG_USER_DHRYSTONE_DHRYSTONE)      += dhrystone
dir_$(CONFIG_USER_DHCP_ISC_SERVER_DHCPD)    += dhcp-isc
dir_$(CONFIG_USER_DHCP_ISC_CLIENT_DHCLIENT) += dhcp-isc
dir_$(CONFIG_USER_DHCP_ISC_RELAY_DHCRELAY)  += dhcp-isc
dir_$(CONFIG_USER_DHCPCD_DHCPCD)            += dhcpcd
dir_$(CONFIG_USER_DHCPCD_NEW_DHCPCD)        += dhcpcd-new
dir_$(CONFIG_USER_DHCPD_DHCPD)              += dhcpd
dir_$(CONFIG_USER_DIALD_DIALD)              += diald
dir_$(CONFIG_USER_DISCARD_DISCARD)          += discard
dir_$(CONFIG_USER_DISCARD_ECHO)             += discard
dir_$(CONFIG_USER_DOSFSTOOLS_MKDOSFS)       += dosfstools
dir_$(CONFIG_USER_DOSFSTOOLS_DOSFSCK)       += dosfstools
ifneq ($(CONFIG_USER_DNSMASQ2_DNSMASQ2),y)
dir_$(CONFIG_USER_DNSMASQ_DNSMASQ)          += dnsmasq
else
dir_$(CONFIG_USER_DNSMASQ2_DNSMASQ2)        += dnsmasq2
endif
dir_$(CONFIG_USER_DROPBEAR_DROPBEAR)        += dropbear
dir_$(CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK)  += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_BADBLOCKS) += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_CHATTR)    += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_DUMPE2FS)  += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_E2LABEL)   += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_FSCK)      += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_LSATTR)    += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_MKE2FS)    += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_MKLOST_FOUND) += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_TUNE2FS)   += e2fsprogs
dir_$(CONFIG_USER_E2FSPROGS_MISC_UUIDGEN)   += e2fsprogs
dir_$(CONFIG_USER_EBTABLES_EBTABLES)        += ebtables
dir_$(CONFIG_USER_ELVISTINY_VI)             += elvis-tiny
dir_$(CONFIG_USER_ETHATTACH_ETHATTACH)      += ethattach
dir_$(CONFIG_USER_ETHERWAKE)				+= etherwake
dir_$(CONFIG_USER_ETHTOOL_ETHTOOL)          += ethtool
dir_$(CONFIG_USER_EXPAT_EXAMPLES)           += expat-examples
dir_$(CONFIG_USER_EXPECT_EXPECT)            += expect
dir_$(CONFIG_USER_EZIPUPDATE_EZIPUPDATE)    += ez-ipupdate
dir_$(CONFIG_USER_FAKEIDENTD_IDENTD)        += fakeidentd
dir_$(CONFIG_USER_FERRET_FERRET)            += ferret
dir_$(CONFIG_USER_FCONFIG_FCONFIG)          += fconfig
dir_$(CONFIG_USER_FDISK_FDISK)              += fdisk
dir_$(CONFIG_USER_FDISK_SFDISK)             += fdisk
dir_$(CONFIG_USER_FILEUTILS_CAT)            += fileutils
dir_$(CONFIG_USER_FILEUTILS_CHGRP)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_CHMOD)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_CHOWN)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_CMP)            += fileutils
dir_$(CONFIG_USER_FILEUTILS_CP)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_DD)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_GREP)           += fileutils
dir_$(CONFIG_USER_FILEUTILS_L)              += fileutils
dir_$(CONFIG_USER_FILEUTILS_LN)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_LS)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_MKDIR)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_MKFIFO)         += fileutils
dir_$(CONFIG_USER_FILEUTILS_MKNOD)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_MORE)           += fileutils
dir_$(CONFIG_USER_FILEUTILS_MV)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_RM)             += fileutils
dir_$(CONFIG_USER_FILEUTILS_RMDIR)          += fileutils
dir_$(CONFIG_USER_FILEUTILS_SYNC)           += fileutils
dir_$(CONFIG_USER_FILEUTILS_TOUCH)          += fileutils
dir_$(CONFIG_USER_FNORD_HTTPD)              += fnord
dir_$(CONFIG_USER_FLASHW_FLASHW)            += flashw
dir_$(CONFIG_USER_FLATFSD_FLATFSD)          += flatfsd
dir_$(CONFIG_USER_FLTHDR_FLTHDR)            += flthdr
dir_$(CONFIG_USER_FREESWAN)                 += freeswan
dir_$(CONFIG_USER_FROB_LED_FROB_LED)        += frob-led
dir_$(CONFIG_USER_FROX_FROX)                += frox
dir_$(CONFIG_USER_FSWCERT_FSWCERT)          += fswcert
dir_$(CONFIG_USER_FTP_FTP_FTP)              += ftp
dir_$(CONFIG_USER_FTPD_FTPD)                += ftpd
dir_$(CONFIG_USER_GDBSERVER_GDBREPLAY)      += gdbserver
dir_$(CONFIG_USER_GDBSERVER_GDBSERVER)      += gdbserver
dir_$(CONFIG_USER_GDB_HOST)		    += gdb
dir_$(CONFIG_USER_GDB_GDBREPLAY)            += gdb
dir_$(CONFIG_USER_GDB_GDBSERVER)            += gdb
dir_$(CONFIG_USER_GDB_TARGET)		    += gdb
dir_$(CONFIG_USER_GETTYD_GETTYD)            += gettyd
dir_$(CONFIG_USER_GNUGK_GNUGK)              += gnugk
dir_$(CONFIG_USER_GREP_GREP)                += grep
dir_$(CONFIG_USER_HASERL_HASERL)            += haserl
dir_$(CONFIG_USER_HD_HD)                    += hd
dir_$(CONFIG_USER_HDPARM_HDPARM)            += hdparm
dir_$(CONFIG_USER_LOAD_LOAD)                += load
dir_$(CONFIG_USER_HOSTAP_HOSTAP)            += hostap
dir_$(CONFIG_USER_HOSTAP_HOSTAP)            += hostap/utils
dir_$(CONFIG_USER_HOSTAP_HOSTAPD)           += hostap/hostapd
dir_$(CONFIG_USER_HPING_HPING)              += hping
dir_$(CONFIG_USER_HTTPD_HTTPD)              += httpd
dir_$(CONFIG_USER_HTTPTUNNEL_CLIENT)        += httptunnel
dir_$(CONFIG_USER_HTTPTUNNEL_SERVER)        += httptunnel
dir_$(CONFIG_USER_HWCLOCK_HWCLOCK)          += hwclock
dir_$(CONFIG_USER_IFATTACH_IFATTACH)        += ifattach
dir_$(CONFIG_USER_IPERF_IPERF)              += iperf
dir_$(CONFIG_USER_INETD_INETD)              += inetd
dir_$(CONFIG_USER_INIT_EXPAND)              += init
dir_$(CONFIG_USER_INIT_INIT)                += init
dir_$(CONFIG_USER_IPCHAINS_IPCHAINS)        += ipchains
dir_$(CONFIG_USER_IPFWADM_IPFWADM)          += ipfwadm
dir_$(CONFIG_USER_IPMASQADM_IPMASQADM)      += ipmasqadm
dir_$(CONFIG_USER_IPPORTFW_IPPORTFW)        += ipportfw
dir_$(CONFIG_USER_IPREDIR_IPREDIR)          += ipredir
dir_$(CONFIG_USER_IPROUTE2)                 += iproute2
dir_$(CONFIG_USER_IPSENTINEL_IPSENTINEL)    += ip-sentinel
dir_$(CONFIG_USER_IPSET_IPSET)              += ipset
dir_$(CONFIG_USER_IPTABLES_IPTABLES)        += iptables
dir_$(CONFIG_USER_IPTABLES_IP6TABLES)       += iptables
dir_$(CONFIG_USER_IPUTILS_IPUTILS)          += iputils
dir_$(CONFIG_USER_JAMVM_JAMVM)              += jamvm
dir_$(CONFIG_USER_JPEGVIEW_JPEGVIEW)        += jpegview
dir_$(CONFIG_USER_JQUERY_UI)                += jquery-ui
dir_$(CONFIG_USER_KENDIN_CONFIG)            += kendin-config
dir_$(CONFIG_USER_KEXEC_KEXEC)              += kexec-tools
dir_$(CONFIG_USER_KLAXON_KLAXON)            += klaxon
dir_$(CONFIG_USER_LANBYPASS_LANBYPASS)      += lanbypass
dir_$(CONFIG_USER_LAYER7_PROTOCOLS)         += l7-protocols
dir_$(CONFIG_USER_L2TPD_L2TPD)              += l2tpd
dir_$(CONFIG_USER_LANG_A60)                 += a60
dir_$(CONFIG_USER_LCD_LCD)                  += lcd
dir_$(CONFIG_USER_LEDCMD_LEDCMD)            += ledcmd
dir_$(CONFIG_USER_LEDCON_LEDCON)            += ledcon
dir_$(CONFIG_USER_LEVEE_VI)                 += levee
dir_$(CONFIG_USER_LHA_LHA)                  += lha
dir_$(CONFIG_USER_LINUXIGD_LINUXIGD)        += linux-igd
dir_$(CONFIG_USER_LILO_LILO)                += lilo
dir_$(CONFIG_USER_LIRC)                     += lirc
dir_$(CONFIG_USER_LISSA_LISSA)              += lissa
dir_$(CONFIG_USER_LM_SENSORS)               += lm_sensors
dir_$(CONFIG_USER_LOATTACH_LOATTACH)        += loattach
dir_$(CONFIG_USER_LOGIN_LOGIN)              += login
dir_$(CONFIG_USER_LOGIN_PASSWD)             += login
dir_$(CONFIG_USER_LOGROTATE_LOGROTATE)      += logrotate
dir_$(CONFIG_USER_LPR)                      += lpr
dir_$(CONFIG_USER_LRPSTAT_LRPSTAT)          += lrpstat
dir_$(CONFIG_USER_LRZSZ_LRZSZ)              += lrzsz
dir_$(CONFIG_USER_LSOF_LSOF)                += lsof
dir_$(CONFIG_USER_MAIL_MAIL_IP)             += mail
dir_$(CONFIG_USER_MATH_TEST)                += mathtest
dir_$(CONFIG_USER_MAWK_AWK)                 += mawk
dir_$(CONFIG_USER_MGETTY_MGETTY)            += mgetty
dir_$(CONFIG_USER_MTDUTILS)                 += mtd-utils
dir_$(CONFIG_USER_MICROWIN)                 += microwin
dir_$(CONFIG_USER_MINI_HTTPD_MINI_HTTPD)    += mini_httpd
dir_$(CONFIG_USER_MINIUPNPD)                += miniupnpd
dir_$(CONFIG_USER_MOUNT_MOUNT)              += mount
dir_$(CONFIG_USER_MOUNT_UMOUNT)             += mount
dir_$(CONFIG_USER_MP3PLAY_MP3PLAY)          += mp3play
dir_$(CONFIG_USER_MSNTP_MSNTP)              += msntp
dir_$(CONFIG_USER_MUSICBOX_MUSICBOX)        += musicbox
dir_$(CONFIG_USER_MYSQL)                    += mysql
dir_$(CONFIG_USER_NBENCH_NBENCH)            += nbench
dir_$(CONFIG_USER_NESSUS_NASL)              += nessus
dir_$(CONFIG_USER_NESSUS_CORE)              += nessus
dir_$(CONFIG_USER_NESSUS_PLUGINS)           += nessus
dir_$(CONFIG_USER_NESSUS_LIBRARIES)         += nessus
dir_$(CONFIG_USER_NETCAT_NETCAT)            += netcat
dir_$(CONFIG_USER_NETFLASH_NETFLASH)        += netflash
dir_$(CONFIG_USER_NETPERF_NETPERF)          += netperf
dir_$(CONFIG_USER_NETPERF_NETSERVER)        += netperf
dir_$(CONFIG_USER_NETPIPE_NETPIPE)          += netpipe
dir_$(CONFIG_USER_NET_TOOLS_ARP)            += net-tools
dir_$(CONFIG_USER_NET_TOOLS_HOSTNAME)       += net-tools
dir_$(CONFIG_USER_NET_TOOLS_IFCONFIG)       += net-tools
dir_$(CONFIG_USER_NET_TOOLS_NAMEIF)         += net-tools
dir_$(CONFIG_USER_NET_TOOLS_NETSTAT)        += net-tools
dir_$(CONFIG_USER_NET_TOOLS_PLIPCONFIG)     += net-tools
dir_$(CONFIG_USER_NET_TOOLS_RARP)           += net-tools
dir_$(CONFIG_USER_NET_TOOLS_ROUTE)          += net-tools
dir_$(CONFIG_USER_NET_TOOLS_SLATTACH)       += net-tools
dir_$(CONFIG_USER_NET_TOOLS_IPMADDR)        += net-tools
dir_$(CONFIG_USER_NET_TOOLS_IPTUNNEL)       += net-tools
dir_$(CONFIG_USER_NET_TOOLS_MII_TOOL)       += net-tools
dir_$(CONFIG_USER_NET_TOOLS_MII_TOOL_FEC)   += mii-tool-fec
dir_$(CONFIG_USER_NETSTAT_NAT_NETSTAT_NAT)  += netstat-nat
dir_$(CONFIG_USER_NOOOM_NOOOM)              += nooom
dir_$(CONFIG_USER_NMAP_NMAP)                += nmap
dir_$(CONFIG_USER_NTPCLIENT_NTPCLIENT)      += ntpclient
dir_$(CONFIG_USER_NTPCLIENT_ADJTIMEX)       += ntpclient
dir_$(CONFIG_USER_NTPD_NTPD)                += ntp
dir_$(CONFIG_USER_NTPD_NTPDATE)             += ntp
dir_$(CONFIG_USER_NTPD_NTPQ)                += ntp
dir_$(CONFIG_USER_NULL_NULL)                += null
dir_$(CONFIG_USER_NWSH_SH)                  += nwsh
dir_$(CONFIG_USER_MSH_SH)                   += msh
dir_$(CONFIG_USER_OGGPLAY_EXAMPLE)          += oggplay
dir_$(CONFIG_USER_OGGPLAY_OGGPLAY)          += oggplay
dir_$(CONFIG_USER_OPENSSL_APPS)             += openssl
dir_$(CONFIG_USER_OPENSWAN)                 += openswan
dir_$(CONFIG_USER_OPENVPN_OPENVPN)          += openvpn
dir_$(CONFIG_USER_OPROFILE)                 += oprofile
dir_$(CONFIG_USER_P7ZIP_7ZA)                += p7zip
dir_$(CONFIG_USER_PALMBOT_PALMBOT)          += palmbot
dir_$(CONFIG_USER_PAM_LDAP)                 += pam_ldap
dir_$(CONFIG_USER_PAM_RADIUS)               += pam_radius
dir_$(CONFIG_USER_PAM_SMB)                  += pam_smb
dir_$(CONFIG_USER_PAM_TACACS)               += pam_tacplus
dir_$(CONFIG_USER_PAM_KRB5)					+= pam_krb5
dir_$(CONFIG_USER_PCIUTILS_LSPCI)           += pciutils
dir_$(CONFIG_USER_PCIUTILS_SETPCI)          += pciutils
dir_$(CONFIG_USER_PCMCIA_CS)                += pcmcia-cs
dir_$(CONFIG_USER_PERL_PERL)                += perl/Cross
dir_$(CONFIG_USER_PING_PING)                += ping
dir_$(CONFIG_USER_PLAY_PLAY)                += play
dir_$(CONFIG_USER_PLAY_TONE)                += play
dir_$(CONFIG_USER_PLAYRT_PLAYRT)            += playrt
dir_$(CONFIG_USER_PLUG_PLUG)                += plug
dir_$(CONFIG_USER_POP3PROXY_POP3PROXY)      += pop3proxy
dir_$(CONFIG_USER_PORTMAP_PORTMAP)          += portmap
dir_$(CONFIG_USER_POTRACE_POTRACE)          += potrace
dir_$(CONFIG_USER_PPPD_PPPD_PPPD)           += pppd
dir_$(CONFIG_USER_PPTP_PPTP)                += pptp
dir_$(CONFIG_USER_PPTP_CLIENT_PPTP)         += pptp-client
dir_$(CONFIG_USER_PPTP_CLIENT_PPTP_CALLMGR) += pptp-client
dir_$(CONFIG_USER_PPTPD_PPTPCTRL)           += pptpd
dir_$(CONFIG_USER_PPTPD_PPTPD)              += pptpd
dir_$(CONFIG_USER_PROCPS_FREE)              += procps
dir_$(CONFIG_USER_PROCPS_KILL)              += procps
dir_$(CONFIG_USER_PROCPS_PGREP)             += procps
dir_$(CONFIG_USER_PROCPS_PKILL)             += procps
dir_$(CONFIG_USER_PROCPS_PS)                += procps
dir_$(CONFIG_USER_PROCPS_SKILL)             += procps
dir_$(CONFIG_USER_PROCPS_SNICE)             += procps
dir_$(CONFIG_USER_PROCPS_SYSCTL)            += procps
dir_$(CONFIG_USER_PROCPS_TLOAD)             += procps
dir_$(CONFIG_USER_PROCPS_TOP)               += procps
dir_$(CONFIG_USER_PROCPS_UPTIME)            += procps
dir_$(CONFIG_USER_PROCPS_VMSTAT)            += procps
dir_$(CONFIG_USER_PROCPS_W)                 += procps
dir_$(CONFIG_USER_PROCPS_WATCH)             += procps
dir_$(CONFIG_USER_PROFTPD_PROFTPD)          += proftpd
dir_$(CONFIG_USER_PYTHON_PYTHON)            += python
dir_$(CONFIG_USER_QSPITEST_TEST)            += qspitest
dir_$(CONFIG_USER_QSPITEST_RX)              += qspitest
dir_$(CONFIG_USER_QUAGGA_ZEBRA_ZEBRA)       += quagga
dir_$(CONFIG_USER_RADVD_RADVD)              += radvd
dir_$(CONFIG_USER_RADAUTH_RADAUTH)          += radauth
dir_$(CONFIG_USER_RDATE_RDATE)              += rdate
dir_$(CONFIG_USER_RAMIMAGE_RAMFS64)         += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS128)        += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS256)        += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS512)        += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS1024)       += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS2048)       += ramimage
dir_$(CONFIG_USER_RAMIMAGE_RAMFS8192)       += ramimage
dir_$(CONFIG_USER_READPROFILE_READPROFILE)  += readprofile
dir_$(CONFIG_USER_RECOVER_RECOVER)          += recover
dir_$(CONFIG_USER_REISERFSPROGS)            += reiserfsprogs
dir_$(CONFIG_USER_ROOTLOADER_ROOTLOADER)    += rootloader
dir_$(CONFIG_USER_ROUTED_ROUTED)            += routed
dir_$(CONFIG_USER_RP_PPPOE_PPPOE)           += rp-pppoe
dir_$(CONFIG_USER_RP_PPPOE_PPPOE_SERVER)    += rp-pppoe
dir_$(CONFIG_USER_RRDTOOL_RRDTOOL)          += rrdtool
dir_$(CONFIG_USER_RSYNC_RSYNC)              += rsync
dir_$(CONFIG_USER_RSYSLOG_RSYSLOGD)         += rsyslog
dir_$(CONFIG_USER_RSYSLOGD_RSYSLOGD)        += rsyslogd
dir_$(CONFIG_USER_RTC_M41T11)               += rtc-m41t11
dir_$(CONFIG_USER_RTC_DS1302)               += rtc-ds1302
dir_$(CONFIG_USER_SAMBA)                    += samba
dir_$(CONFIG_USER_SASH_REBOOT)              += sash
dir_$(CONFIG_USER_SASH_SH)                  += sash
dir_$(CONFIG_USER_SASH_SHUTDOWN)            += sash
dir_$(CONFIG_USER_SASH_REBOOT_SNAPGEAR)     += sash
dir_$(CONFIG_USER_SENDIP_SENDIP)            += sendip
dir_$(CONFIG_USER_SER_SER)                  += ser
dir_$(CONFIG_USER_SER_RTPPROXY)             += ser
dir_$(CONFIG_USER_SETHDLC_SETHDLC)          += sethdlc
dir_$(CONFIG_USER_SETMAC_SETMAC)            += setmac
dir_$(CONFIG_USER_SETSERIAL_SETSERIAL)      += setserial
dir_$(CONFIG_USER_SGUTOOL_SGUTOOL)          += sgutool
dir_$(CONFIG_USER_SH_SH)                    += sh
dir_$(CONFIG_USER_SHADOW_UTILS)             += shadow
dir_$(CONFIG_USER_SHUTILS_BASENAME)         += shutils
dir_$(CONFIG_USER_SHUTILS_DATE)             += shutils
dir_$(CONFIG_USER_SHUTILS_DIRNAME)          += shutils
dir_$(CONFIG_USER_SHUTILS_ECHO)             += shutils
dir_$(CONFIG_USER_SHUTILS_FALSE)            += shutils
dir_$(CONFIG_USER_SHUTILS_LOGNAME)          += shutils
dir_$(CONFIG_USER_SHUTILS_PRINTENV)         += shutils
dir_$(CONFIG_USER_SHUTILS_PWD)              += shutils
dir_$(CONFIG_USER_SHUTILS_TRUE)             += shutils
dir_$(CONFIG_USER_SHUTILS_UNAME)            += shutils
dir_$(CONFIG_USER_SHUTILS_WHICH)            += shutils
dir_$(CONFIG_USER_SHUTILS_WHOAMI)           += shutils
dir_$(CONFIG_USER_SHUTILS_YES)              += shutils
dir_$(CONFIG_USER_SIPROXD_SIPROXD)          += siproxd
dir_$(CONFIG_USER_SLATTACH_SLATTACH)        += slattach
dir_$(CONFIG_USER_SMBMOUNT_SMBMOUNT)        += smbmount
dir_$(CONFIG_USER_SMBMOUNT_SMBUMOUNT)       += smbmount
dir_$(CONFIG_USER_SMTP_SMTPCLIENT)          += smtpclient
dir_$(CONFIG_USER_SNMPD_SNMPD)              += snmpd
dir_$(CONFIG_USER_SNORT_SNORT)              += snort
dir_$(CONFIG_USER_SPEEDTOUCH_MODEM_RUN)     += speedtouch/src
dir_$(CONFIG_USER_STUNNEL_STUNNEL)          += stunnel
dir_$(CONFIG_USER_SSLWRAP_SSLWRAP)          += sslwrap
dir_$(CONFIG_USER_SQUID_SQUID)              += squid
dir_$(CONFIG_USER_SQUASHFS_MKSQUASHFS)      += squashfs
dir_$(CONFIG_USER_SQUASHFS_MKSQUASHFS7Z)    += squashfs
dir_$(CONFIG_USER_SSCEP)					+= sscep
dir_$(CONFIG_USER_SSH_SSHD)                 += ssh
dir_$(CONFIG_USER_SSH_SSH)                  += ssh
dir_$(CONFIG_USER_SSH_SSHKEYGEN)            += ssh
dir_$(CONFIG_USER_STP_STP)                  += stp
dir_$(CONFIG_USER_STRACE_STRACE)            += strace
dir_$(CONFIG_USER_STTY_STTY)                += stty
dir_$(CONFIG_USER_SYSUTILS_DF)              += sysutils
dir_$(CONFIG_USER_SYSUTILS_FREE)            += sysutils
dir_$(CONFIG_USER_SYSUTILS_HOSTNAME)        += sysutils
dir_$(CONFIG_USER_SYSUTILS_KILL)            += sysutils
dir_$(CONFIG_USER_SYSUTILS_PS)              += sysutils
dir_$(CONFIG_USER_SYSUTILS_REBOOT)          += sysutils
dir_$(CONFIG_USER_SYSUTILS_SHUTDOWN)        += sysutils
dir_$(CONFIG_USER_TCPBLAST_TCPBLAST)        += tcpblast
dir_$(CONFIG_USER_TCPWRAP_TCPD)             += tcpwrappers
dir_$(CONFIG_USER_TCPDUMP_TCPDUMP)          += tcpdump
dir_$(CONFIG_USER_TCSH_TCSH)                += tcsh
dir_$(CONFIG_USER_TELNET_TELNET)            += telnet
dir_$(CONFIG_USER_TELNETD_TELNETD)          += telnetd
dir_$(CONFIG_USER_TFTP_TFTP)                += tftp
dir_$(CONFIG_USER_TFTPD_TFTPD)              += tftpd
dir_$(CONFIG_USER_THREADDEMOS_THREADDEMOS)  += threaddemos
dir_$(CONFIG_USER_THTTPD_THTTPD)            += thttpd
dir_$(CONFIG_USER_TINYLOGIN_CRYPT_CRYPT)    += tinylogin
dir_$(CONFIG_USER_TINYLOGIN_TINYLOGIN)      += tinylogin
dir_$(CONFIG_USER_TINYPROXY_TINYPROXY)      += tinyproxy
dir_$(CONFIG_USER_TINYTCL_TCLSH)            += tinytcl
dir_$(CONFIG_USER_TIP_TIP)                  += tip
dir_$(CONFIG_USER_TIMEPEG_TPT)              += tpt
dir_$(CONFIG_USER_TRACEROUTE_TRACEROUTE)    += traceroute
dir_$(CONFIG_USER_TRIPWIRE_SIGGEN)          += tripwire
dir_$(CONFIG_USER_TRIPWIRE_TRIPWIRE)        += tripwire
dir_$(CONFIG_USER_NETSNMP_SNMPD)            += net-snmp
dir_$(CONFIG_USER_UDEV)                     += udev
dir_$(CONFIG_USER_ULOGD_ULOGD)              += ulogd
dir_$(CONFIG_USER_ULOGD2_ULOGD)             += ulogd2
dir_$(CONFIG_USER_UNRAR_UNRAR)              += unrar
dir_$(CONFIG_USER_UNZIP_UNZIP)              += unzip
dir_$(CONFIG_USER_UNZOO_UNZOO)              += unzoo
dir_$(CONFIG_USER_USBCBI_USBCBI)            += cbi_client
dir_$(CONFIG_USER_USBHUBCTRL_USBHUBCTRL)	+= usbhubctrl
dir_$(CONFIG_USER_USBISO_USBISO)            += iso_client
dir_$(CONFIG_USER_VERSION_VERSION)          += version
dir_$(CONFIG_USER_VCONFIG_VCONFIG)          += vconfig
dir_$(CONFIG_USER_VIXIECRON_CRON)           += vixie-cron
dir_$(CONFIG_USER_VIXIECRON_CRONTAB)        += vixie-cron
dir_$(CONFIG_USER_VPLAY_VPLAY)              += vplay
dir_$(CONFIG_USER_VPLAY_VREC)               += vplay
dir_$(CONFIG_USER_VPLAY_MIXER)              += vplay
dir_$(CONFIG_USER_VPNLED_VPNLED)            += vpnled
dir_$(CONFIG_USER_W3CAM_VIDCAT)             += w3cam
dir_$(CONFIG_USER_W3CAM_W3CAMD)             += w3cam
dir_$(CONFIG_USER_WATCHDOGD)                += watchdogd
dir_$(CONFIG_USER_WGET)                     += wget
dir_$(CONFIG_USER_UVCCAPTURE)               += uvccapture
dir_$(CONFIG_USER_WHETSTONE_WHETSTONE)      += whetstone
dir_$(CONFIG_USER_WIRELESS_TOOLS)           += wireless_tools
dir_$(CONFIG_USER_WLAN_NG)                  += wlan-ng
dir_$(CONFIG_USER_XL2TPD_XL2TPD)            += xl2tpd
dir_$(CONFIG_USER_ZEBRA_BGPD_BGPD)          += zebra
dir_$(CONFIG_USER_ZEBRA_OSPFD_OSPFD)        += zebra
dir_$(CONFIG_USER_ZEBRA_RIPD_RIPD)          += zebra
dir_$(CONFIG_USER_ZEBRA_ZEBRA_ZEBRA)        += zebra

dir_y += games

-include Makefile.local
-include Makefile.auto

ifdef HOSTBUILD
# only build the dirs with hostbuild support
hostdir = $(patsubst %/hostbuild.mak,%,$(wildcard */hostbuild.mak))
dir_y := $(filter $(hostdir),$(dir_y))
dir_n := $(filter $(hostdir),$(dir_n))
dir_ := $(filter $(hostdir),$(dir_))
dir_p :=
dir_v :=
endif

all:
	$(MAKE) -j$(HOST_NCPU) $(sort $(dir_y) $(dir_v) $(dir_p)) || exit $$?

#
# add directory dependancies here
#
.PHONY: $(sort $(dir_y) $(dir_p))
snort: mysql
asterisk-addons: mysql asterisk
miniupnpd : iptables

$(sort $(dir_y) $(dir_p)):
	[ ! -d "$@" ] || ( touch $@/.sgbuilt_user && $(MAKE) $(SUBDIR_SMP_BUILD) -C $@ ) || exit $$?

%_only:
	touch $(@:_only=)/.sgbuilt_user && $(MAKE) -j$(HOST_NCPU) $(SUBDIR_SMP_BUILD) -C $(@:_only=)

%_clean:
	$(MAKE) -j1 -C $(@:_clean=) clean; rm -f $(@:_clean=)/.sgbuilt_user; true

%_romfs:
	$(MAKE) $(SUBDIR_SMP_BUILD) -C $(@:_romfs=) romfs

romfs:
	for i in $(sort $(dir_y)) $(dir_p) ; do \
		[ ! -d $$i ] || $(MAKE) $(SUBDIR_SMP_BUILD) -C $$i romfs || exit $$? ; \
	done

clean:
	-for i in $(dir_v) $(sort $(dir_y) $(dir_n) $(dir_)) $(dir_p) ; do \
		if [ -f $$i/.sgbuilt_user ]; then \
			$(MAKE) -j1 -C $$i clean ; \
			rm -f $$i/.sgbuilt_user; \
		fi; \
	done

prune:
	-for i in $(sort $(dir_n) $(dir_)) ; do \
		found=0; \
		for j in $(sort $(dir_y)) ; do \
			if [ $$i = $$j ]; then \
				found=1; \
			fi; \
		done; \
		if [ $$found = 0 ]; then \
			[ "$$i" = "freeswan" ] && make prune_freeswan; \
			[ "$$i" = "openswan" ] && make prune_openswan; \
			rm -fr $$i; \
		fi; \
	done

prune_freeswan:
	@cd $(ROOTDIR); \
	mkdir $@; \
	cp --parents freeswan/klips/net/ipsec/Config.in $@/; \
	rm -fr freeswan; \
	cp -R $@/* .; \
	rm -fr $@

prune_openswan:
	@cd $(ROOTDIR); \
	mkdir $@; \
	cp --parents openswan/linux/net/ipsec/{Config.in*,Kconfig,Makefile*,aes/Makefile*,des/Makefile*} $@/; \
	rm -fr openswan; \
	cp -R $@/* .; \
	rm -fr $@


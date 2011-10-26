#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16520);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_26777";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_26777 .
(Sec. Vulnerability in SNMP (rev. 16))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_26777
See also : HPUX security bulletin 184
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_26777";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "HP-UX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 800:10.00 700:10.00 800:10.10 700:10.10 800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_26777 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"	OVNNMgr.OVNNM-RUN,B.04.11.00 OVNNMgr.OVNNMGR-JPN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVCI-RUN", version:"	OVPlatform.OVCI-RUN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"	OVPlatform.OVEVENT-MIN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"	OVPlatform.OVMIN,B.04.11.00 OVPlatform.OVPMD-MIN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVSNMP-MIN", version:"	OVPlatform.OVSNMP-MIN,B.04.11.00 OVPlatform.OVWIN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevKit.OVMIN-PRG", version:"	OVPlatformDevKit.OVMIN-PRG,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevKit.OVWIN-PRG", version:"	OVPlatformDevKit.OVWIN-PRG,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevMan.OVWIN-PRG-MAN", version:"	OVPlatformDevMan.OVWIN-PRG-MAN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPDevKit.OVSNMP-PRG", version:"	OVSNMPDevKit.OVSNMP-PRG,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}

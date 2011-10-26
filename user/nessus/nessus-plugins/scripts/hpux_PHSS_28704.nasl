#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16994);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_28704";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_28704 .
(SSRT2393 rev.2 HP-UX Apache Vulnerabilities)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_28704
See also : HPUX security bulletin 224
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_28704";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "HP-UX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_28704 PHSS_28877 PHSS_29205 PHSS_29428 PHSS_29753 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVMIB-CONTRIB", version:"	OVNNMgr.OVMIB-CONTRIB,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"	OVNNMgr.OVNNM-RUN,B.06.20.00 OVNNMgr.OVNNMGR-JPN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVRPT-RUN", version:"	OVNNMgr.OVRPT-RUN,B.06.20.00 OVNNMgr.OVWWW-JPN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"	OVNNMgrMan.OVNNM-RUN-MAN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"	OVPlatform.OVEVENT-MIN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"	OVPlatform.OVMIN,B.06.20.00 OVPlatform.OVSNMP-MIN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWIN", version:"	OVPlatform.OVWIN,B.06.20.00 OVPlatform.OVWWW-EVNT,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-FW", version:"	OVPlatform.OVWWW-FW,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-SRV", version:"	OVPlatform.OVWWW-SRV,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevKit.OVWIN-PRG", version:"	OVPlatformDevKit.OVWIN-PRG,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVEVENTMIN-MAN", version:"	OVPlatformMan.OVEVENTMIN-MAN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVMIN-MAN", version:"	OVPlatformMan.OVMIN-MAN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVWIN-MAN", version:"	OVPlatformMan.OVWIN-MAN,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}

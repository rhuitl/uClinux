#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16643);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_24797";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24797 .
(Sec. Vulnerability in OV NNM)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_24797
See also : HPUX security bulletin 177
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24797";
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

if ( hpux_patch_installed (patches:"PHSS_24797 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVMIB-CONTRIB", version:"	OVNNMgr.OVMIB-CONTRIB,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"	OVNNMgr.OVNNM-RUN,B.06.10.00 OVNNMgr.OVNNMGR-JPN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVWWW-JPN", version:"	OVNNMgr.OVWWW-JPN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"	OVNNMgrMan.OVNNM-RUN-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNMWELENGDOC", version:"	OVNNMgrRtDOC.OVNNMWELENGDOC,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVDB-RUN", version:"	OVPlatform.OVDB-RUN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"	OVPlatform.OVEVENT-MIN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"	OVPlatform.OVMIN,B.06.10.00 OVPlatform.OVPMD-MIN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVRPT-RUN", version:"	OVPlatform.OVRPT-RUN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVSNMP-MIN", version:"	OVPlatform.OVSNMP-MIN,B.06.10.00 OVPlatform.OVWIN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWIN-BGROUND", version:"	OVPlatform.OVWIN-BGROUND,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-EVNT", version:"	OVPlatform.OVWWW-EVNT,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-FW", version:"	OVPlatform.OVWWW-FW,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevKit.OVWIN-PRG", version:"	OVPlatformDevKit.OVWIN-PRG,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformDevMan.OVWIN-PRG-MAN", version:"	OVPlatformDevMan.OVWIN-PRG-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVEVENTMIN-MAN", version:"	OVPlatformMan.OVEVENTMIN-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVMIN-MAN", version:"	OVPlatformMan.OVMIN-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVSNMP-MIN-MAN", version:"	OVPlatformMan.OVSNMP-MIN-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVWIN-MAN", version:"	OVPlatformMan.OVWIN-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPDevKit.OVSNMP-PRG", version:"	OVSNMPDevKit.OVSNMP-PRG,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPDevMan.OVSNMP-PRG-MAN", version:"	OVSNMPDevMan.OVSNMP-PRG-MAN,B.06.10.00") )
{
 security_hole(0);
 exit(0);
}

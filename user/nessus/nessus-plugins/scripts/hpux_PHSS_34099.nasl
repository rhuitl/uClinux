#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20868);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_34099";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_34099 .
(SSRT5911 rev.1 - HP OpenView Network Node Manager (OV NNM) Remote Unauthorized Privileged Access, Arbitrary Command Execution, Arbitrary File Creation)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHSS_34099
See also : HPUX security bulletin 2098
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_34099";
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

if ( ! hpux_check_ctx ( ctx:"800:11.23 700:11.23 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_34099 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-CORE", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-IPV6", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-JPN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-KOR", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-PD", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-PESA", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMETCore.OVNNMET-SCH", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVMIB-CONTRIB", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNMGR-JPN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNMGR-KOR", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVNNMGR-SCH", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVRPT-RUN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVWWW-JPN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVWWW-KOR", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgr.OVWWW-SCH", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNM-DOC-REUS", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNM-ENG-DOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNM-JPN-DOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNM-KOR-DOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNM-SCH-DOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNMWELENGDOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNMWELJPNDOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNMWELKORDOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrRtDOC.OVNNMWELSCHDOC", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVDB-RUN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVSNMP-MIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-EVNT", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-FW", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-SRV", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVMIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVPMD-MIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVSNMP-MIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVWIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}

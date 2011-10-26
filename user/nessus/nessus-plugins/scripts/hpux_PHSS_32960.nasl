#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22177);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_32960";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_32960 .
(SSRT051024 rev.1 - HP-UX Running Xserver Local Execution of Arbitrary Code, Privilege Elevation)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_32960
See also : HPUX security bulletin 2137
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_32960";
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

if ( hpux_patch_installed (patches:"PHSS_32960 PHSS_35253 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Xserver.OEM-SERVER", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.OEM-SERVER-PA", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.AGRM", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-ADVANCED", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-ENTRY", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-LOAD", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-SAM", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-SLS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-UTILS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.X11-SERV", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.X11-SERV-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DBE", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DBE-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DPMS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DPMS-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-HPCR", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-HPCR-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-MBX", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-RECORD", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17080);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_30586";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30586 .
(SSRT4692 rev.0 HP-UX XFree86 remote unauthorized privileged access)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHSS_30586
See also : HPUX security bulletin 1018
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30586";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_30586 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Xserver.AGRM", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-ADVANCED", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-ENTRY", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-LOAD", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-SAM", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-SLS", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.DDX-UTILS", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.X11-SERV", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.X11-SERV-MAN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DBE", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DBE-MAN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DPMS", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-DPMS-MAN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-HPCR", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-HPCR-MAN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-MBX", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Xserver.XEXT-RECORD", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}

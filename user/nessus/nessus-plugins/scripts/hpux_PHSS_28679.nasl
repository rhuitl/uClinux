#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17495);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_28679";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_28679 .
(SSRT2373 SSRT2374 SSRT3484 SSRT2405 SSRT2415 rev.2 CDE)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_28679
See also : HPUX security bulletin 263
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_28679";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_28679 PHSS_29739 PHSS_30790 PHSS_32112 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:"B.11.11.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:"B.11.11.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:"B.11.11.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:"B.11.11.02") )
{
 security_hole(0);
 exit(0);
}

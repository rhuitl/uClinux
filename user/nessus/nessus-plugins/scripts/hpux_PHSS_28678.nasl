#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17494);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_28678";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_28678 .
(SSRT2373 SSRT2374 SSRT3484 SSRT2405 SSRT2415 rev.2 CDE)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_28678
See also : HPUX security bulletin 263
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_28678";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_28678 PHSS_29738 PHSS_32108 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-HELP-PRG", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-HELP-PRG", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}

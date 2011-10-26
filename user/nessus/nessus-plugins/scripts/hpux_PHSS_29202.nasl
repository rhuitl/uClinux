#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17499);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_29202";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_29202 .
(SSRT2373 SSRT2374 SSRT3484 SSRT2405 SSRT2415 rev.2 CDE)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_29202
See also : HPUX security bulletin 263
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_29202";
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

if ( hpux_patch_installed (patches:"PHSS_29202 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDEDevKit.CDE-DEMOS", version:"	CDEDevKit.CDE-DEMOS,B.10.20.00,B.10.20.01,B.10.20.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:"	CDEDevKit.CDE-PRG,B.10.20.00,B.10.20.01,B.10.20.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:"	CDEDevKit.CDE-MAN-DEV,B.10.20.00,B.10.20.01,B.10.20.02") )
{
 security_hole(0);
 exit(0);
}

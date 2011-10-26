#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17436);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_12139";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_12139 .
(Security Vulnerability in CDE on HP-UX 10.0[1,2,3])

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_12139
See also : HPUX security bulletin 072
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_12139";
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

if ( hpux_patch_installed (patches:"PHSS_12139 PHSS_12883 PHSS_14003 PHSS_15796 PHSS_18426 PHSS_20858 PHSS_22340 PHSS_23799 PHSS_25193 PHSS_27878 PHSS_29202 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDEDevKit.CDE-PRG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDEDevKit.CDE-MAN-DEV", version:NULL) )
{
 security_hole(0);
 exit(0);
}

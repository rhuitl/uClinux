#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17019);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHCO_28481";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_28481 .
(SSRT2439 rev.12 HP-UX xdrmem_getbytes())

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_28481
See also : HPUX security bulletin 252
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_28481";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_28481 PHCO_31922 PHCO_32719 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-SHLIBS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

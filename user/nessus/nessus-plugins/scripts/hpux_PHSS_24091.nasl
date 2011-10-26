#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17462);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_24091";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24091 .
(Security Vulnerabilities in CDE on HP-UX)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_24091
See also : HPUX security bulletin 151
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24091";
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

if ( hpux_patch_installed (patches:"PHSS_24091 PHSS_25139 PHSS_25196 PHSS_25788 PHSS_26492 PHSS_27428 PHSS_27872 PHSS_28676 PHSS_29735 PHSS_30011 PHSS_30788 PHSS_32110 PHSS_33325 PHSS_35249 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-SHLIBS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

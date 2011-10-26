#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17066);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_30671";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30671 .
(SSRT4721 rev.0 HP-UX dtlogin unauthorized privileged access, Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30671
See also : HPUX security bulletin 1038
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30671";
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

if ( hpux_patch_installed (patches:"PHSS_30671 PHSS_31832 PHSS_32114 PHSS_32365 PHSS_32455 PHSS_33588 PHSS_35435 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-RUN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

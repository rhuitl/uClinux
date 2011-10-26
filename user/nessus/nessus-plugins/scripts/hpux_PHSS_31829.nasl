#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17556);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_31829";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_31829 .
(SSRT4828 rev.0 remote code execution potential Apache mod_ssl on Virtualvault)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_31829
See also : HPUX security bulletin 1082
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_31829";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_31829 PHSS_32363 PHSS_33788 PHSS_34204 PHSS_35110 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"HP_Webproxy.HPWEB-PX-CORE", version:"A.02.00") )
{
 security_hole(0);
 exit(0);
}

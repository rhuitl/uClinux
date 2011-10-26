#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17520);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHSS_30406";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30406 .
(SSRT4770 rev.0 HP-UX 11.04 running Virtualvault, remote Denial of Service (DoS) and information leakage)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30406
See also : HPUX security bulletin 1053
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30406";
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

if ( hpux_patch_installed (patches:"PHSS_30406 PHSS_30641 PHSS_30945 PHSS_31058 PHSS_31824 PHSS_32182 PHSS_33398 PHSS_34121 PHSS_35109 PHSS_35463 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultWS.WS-CORE", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}

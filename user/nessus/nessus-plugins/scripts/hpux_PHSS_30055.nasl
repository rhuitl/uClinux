#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17511);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_30055";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30055 .
(SSRT4681 Apache 1.3.29 web server on VVOS)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30055
See also : HPUX security bulletin 305
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30055";
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

if ( hpux_patch_installed (patches:"PHSS_30055 PHSS_30639 PHSS_30944 PHSS_31823 PHSS_32140 PHSS_34169 PHSS_35106 PHSS_35308 PHSS_35460 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultTS.VV-IWS", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-CORE-CMN", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}

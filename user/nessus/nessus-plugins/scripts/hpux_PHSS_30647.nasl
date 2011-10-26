#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17070);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_30647";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30647 .
(SSRT4789 rev. 1 HP-UX Apache server remote Denial of Service and bypassing access restrictions)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30647
See also : HPUX security bulletin 1069
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30647";
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

if ( hpux_patch_installed (patches:"PHSS_30647 PHSS_31827 PHSS_32141 PHSS_34171 PHSS_35104 PHSS_35306 PHSS_35458 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultTS.VV-IWS", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VVOS-ADM-RUN", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-CORE-CMN", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}

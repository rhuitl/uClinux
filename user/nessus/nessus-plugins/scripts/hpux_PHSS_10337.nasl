#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16861);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_10337";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_10337 .
(Security Vulnerability in VirtualVault A.01.01)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_10337
See also : HPUX security bulletin 062
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_10337";
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

if ( ! hpux_check_ctx ( ctx:"800:10.16 700:10.16 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_10337 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Netscape-NCS.VAULTTS-NCS", version:"        Netscape-NCS.VAULTTS-NCS,A.01.12.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VAULT-CORE-CMN", version:"        VaultTS.VAULT-CORE-CMN,A.01.01") )
{
 security_hole(0);
 exit(0);
}

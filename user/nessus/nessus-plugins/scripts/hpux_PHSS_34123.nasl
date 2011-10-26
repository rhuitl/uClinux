#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21107);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_34123";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_34123 .
(SSRT051251 rev.2 - Apache-based Web Server on HP-UX mod_ssl, proxy_http, Remote Execution of Arbitrary Code, Denial of Service (DoS), and Unauthorized Access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_34123
See also : HPUX security bulletin 2074
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_34123";
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

if ( hpux_patch_installed (patches:"PHSS_34123 PHSS_34932 PHSS_35436 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultDOC.VV-HTML-MAN", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultWS.WS-CORE", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-IWS-GUI", version:"A.04.70") )
{
 security_hole(0);
 exit(0);
}

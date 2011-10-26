#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17565);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_32362";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_32362 .
(SSRT5902 rev.0 Apache 1.3 on VirtualVault potential remote Denial of Service (DoS) and execution of arbitrary code)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_32362
See also : HPUX security bulletin 1113
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_32362";
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

if ( hpux_patch_installed (patches:"PHSS_32362 PHSS_33074 PHSS_33666 PHSS_34203 PHSS_35111 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"HP_Webproxy.HPWEB-PX-CORE", version:"A.02.10") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16659);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_17484";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_17484 .
(Security Vulnerability in MC/ServiceGuard & MC/LockManager)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHSS_17484
See also : HPUX security bulletin 096
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_17484";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_17484 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"DLMJpn-Clust-Mon.CM-CORE", version:"A.11.05") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLMJpn-Pkg-Mgr.CM-PKG", version:"A.11.05") )
{
 security_hole(0);
 exit(0);
}

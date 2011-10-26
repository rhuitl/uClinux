#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16662);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_17480";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_17480 .
(Security Vulnerability in MC/ServiceGuard & MC/LockManager)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHSS_17480
See also : HPUX security bulletin 096
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_17480";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_17480 PHSS_18148 PHSS_19472 PHSS_20453 PHSS_20577 PHSS_21994 PHSS_23660 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:NULL) )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17548);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHSS_31072";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_31072 .
(SSRT3526 rev.0 Serviceguard potential increase in privilege)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_31072
See also : HPUX security bulletin 1080
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_31072";
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

if ( hpux_patch_installed (patches:"PHSS_31072 PHSS_31076 PHSS_32740 PHSS_33039 PHSS_33835 PHSS_33837 PHSS_34504 PHSS_34760 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE-COM", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG-MAN", version:"A.11.16.00") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17544);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_31067";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_31067 .
(SSRT3526 rev.0 Serviceguard potential increase in privilege)

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/11.X/PHSS_31067
See also : HPUX security bulletin 1080
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_31067";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_31067 PHSS_32243 PHSS_32660 PHSS_32727 PHSS_34505 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ATS-CORE.ATS-RUN", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE-MAN", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}

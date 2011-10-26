#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17546);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_31070";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_31070 .
(SSRT3526 rev.0 Serviceguard potential increase in privilege)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_31070
See also : HPUX security bulletin 1080
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_31070";
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

if ( hpux_patch_installed (patches:"PHSS_31070 PHSS_32246 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-OM.CM-OM", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-DEN-PROV", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-AUTH", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-TOOLS", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"B.02.02.00") )
{
 security_hole(0);
 exit(0);
}

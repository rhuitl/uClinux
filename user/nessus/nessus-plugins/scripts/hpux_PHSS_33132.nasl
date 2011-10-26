#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21658);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_33132";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_33132 .
(SSRT4848 rev.1 - HP-UX Running Motif Applications Remote Arbitrary Code Execution, Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_33132
See also : HPUX security bulletin 2119
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_33132";
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

if ( hpux_patch_installed (patches:"PHSS_33132 PHSS_33550 PHSS_34736 PHSS_35046 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11.X11R6-SHLIBS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF-SHLIB", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SLIBS-IA", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF-SHLIB-IA", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

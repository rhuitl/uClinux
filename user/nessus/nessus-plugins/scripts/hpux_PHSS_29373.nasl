#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16677);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_29373";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_29373 .
(SSRT3589 Potential Security Vulnerability in dtprintinfo)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_29373
See also : HPUX security bulletin 289
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_29373";
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

if ( ! hpux_check_ctx ( ctx:"800:11.22 700:11.22 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_29373 PHSS_30264 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11.MOTIF-SHLIB", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF-SHLIB-IA", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R5-SHLIBS", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SHLIBS", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SLIBS-IA", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}

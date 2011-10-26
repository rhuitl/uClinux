#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17031);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_11628";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_11628 .
(Buffer overflows in X11/Motif libraries)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_11628
See also : HPUX security bulletin 067
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_11628";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_11628 PHSS_12374 PHSS_12824 PHSS_13113 PHSS_13743 PHSS_14040 PHSS_14534 PHSS_15008 PHSS_16120 PHSS_16617 PHSS_17331 PHSS_17323 PHSS_18012 PHSS_19592 PHSS_19963 PHSS_20861 PHSS_21956 PHSS_22944 PHSS_23518 PHSS_25446 PHSS_27229 PHSS_28364 PHSS_28872 PHSS_29126 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11.X11R5-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF12-SHLIB", version:NULL) )
{
 security_hole(0);
 exit(0);
}

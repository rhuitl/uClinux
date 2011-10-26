#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16567);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHCO_26158";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_26158 .
(SSRT3656 rev.1 NLSsuperseded_patches/hp-ux_patches/s700_800/10.X/PHCO_26158 may contain any path)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHCO_26158
See also : HPUX security bulletin 294
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_26158";
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

if ( hpux_patch_installed (patches:"PHCO_26158 PHCO_31920 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.C-MIN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.PROG-MIN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.PROG-AUX", version:NULL) )
{
 security_hole(0);
 exit(0);
}

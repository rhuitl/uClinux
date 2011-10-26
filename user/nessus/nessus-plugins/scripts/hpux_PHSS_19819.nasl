#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16484);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_19819";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_19819 .
(Security Vulnerability in CDE ttsession (Rev.01))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_19819
See also : HPUX security bulletin 103
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_19819";
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

if ( ! hpux_check_ctx ( ctx:"800:10.24 700:10.24 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_19819 PHSS_22546 PHSS_23848 PHSS_24097 PHSS_25419 PHSS_26029 PHSS_28173 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-ENG-A-MSG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-MIN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-HELP-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-PAM", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-TT", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-DTTERM", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-ENG-A-MAN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

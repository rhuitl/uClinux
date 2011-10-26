#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20085);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_33627";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_33627 .
(SSRT051052 rev.1 - HP OpenView Operations and OpenView VantagePoint Java Runtime Environment (JRE) Remote Privileged Access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_33627
See also : HPUX security bulletin 1234
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_33627";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.11 800:11.23 700:11.11 700:11.23 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_33627 PHSS_33864 PHSS_34363 PHSS_34733 PHSS_35228 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-ENG", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-ENG", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-GUI", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-GUI", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-JPN", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-JPN", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-KOR", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-KOR", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SCH", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SCH", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SPA", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SPA", version:"A.08.10.160") )
{
 security_hole(0);
 exit(0);
}

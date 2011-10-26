#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17081);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_30538";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30538 .
(SSRT4727 rev.0 OpenView Operations remote unauthorized access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30538
See also : HPUX security bulletin 1010
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30538";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.11 700:11.11 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_30538 PHSS_30555 PHSS_30979 PHSS_32174 PHSS_32403 PHSS_33143 PHSS_33580 PHSS_33865 PHSS_34294 PHSS_34594 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVOPC-OVW.OVOPC-OVW-MGR", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-OVW.OVOPC-OVW-MGR", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-LIB", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-LIB", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-SVC.OVOPC-SVC-JPN", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-SVC.OVOPC-SVC-JPN", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-GUI-ENG", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-GUI-ENG", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-JPN.OVOPC-GUI-JPN", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-JPN.OVOPC-GUI-JPN", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-UX-MGR78", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC.OVOPC-UX-MGR78", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-ORA", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-ORA", version:"A.07.10") )
{
 security_hole(0);
 exit(0);
}

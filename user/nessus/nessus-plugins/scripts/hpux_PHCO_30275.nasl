#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21131);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHCO_30275";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_30275 .
(SSRT051078 rev.1 - HP-UX usermod(1M) Local UnaUthorized Access. HPSBUX02102 SSRT051078 rev.2 - HP-UX usermod(1M) Local Unauthorized Access.)

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/11.X/PHCO_30275
See also : HPUX security bulletin 2102
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_30275";
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

if ( hpux_patch_installed (patches:"PHCO_30275 PHCO_32181 PHCO_33142 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.ADMN-ENG-A-MAN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.SYS-ADMIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.SYS-ADMIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17085);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHCO_28125";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_28125 .
(SSRT4699 rev.2 HP-UX SAM local privilege increase)

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/11.X/PHCO_28125
See also : HPUX security bulletin 1104
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_28125";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_28125 PHCO_31879 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"InternetSrvcs.INETSVCS-BOOT", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.UX-CORE", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SystemAdmin.OBAM-RUN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SystemAdmin.SAM", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SystemAdmin.SAM-ENG-A-MAN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SystemAdmin.SAM-HELP", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}

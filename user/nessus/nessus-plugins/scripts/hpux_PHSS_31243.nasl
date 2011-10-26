#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16733);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_31243";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_31243 .
(SSRT4699 rev.2 HP-UX SAM local privilege increase)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHSS_31243
See also : HPUX security bulletin 1104
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_31243";
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

if ( hpux_patch_installed (patches:"PHSS_31243 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SystemAdmin.OBAM-RUN", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SystemAdmin.OBAM-RUN-IA", version:"B.11.22") )
{
 security_hole(0);
 exit(0);
}

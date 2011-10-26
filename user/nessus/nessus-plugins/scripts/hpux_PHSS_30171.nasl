#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16495);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHSS_30171";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_30171 .
(SSRT4692 rev.0 HP-UX XFree86 remote unauthorized privileged access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30171
See also : HPUX security bulletin 1018
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_30171";
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

if ( hpux_patch_installed (patches:"PHSS_30171 PHSS_30502 PHSS_30505 PHSS_30872 PHSS_31252 PHSS_32953 PHSS_32960 PHSS_35253 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Xserver.OEM-SERVER", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

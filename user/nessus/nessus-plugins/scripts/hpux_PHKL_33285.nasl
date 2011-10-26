#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19541);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHKL_33285";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_33285 .
(SSRT4702 rev.0 - HP-UX running Veritas 3.3/3.5 unauthorized data access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHKL_33285
See also : HPUX security bulletin 1218
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_33285";
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

if ( hpux_patch_installed (patches:"PHKL_33285 PHKL_33355 PHKL_33920 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"JFS.JFS-BASE2-KRN", version:"3.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"JFS.JFS-BASE2-KRN", version:"3.3") )
{
 security_hole(0);
 exit(0);
}

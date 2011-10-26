#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18395);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHCO_32926";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_32926 .
(SSRT5953 rev.3 - HP-UX passwd(1) Local Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_32926
See also : HPUX security bulletin 2103
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_32926";
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

if ( hpux_patch_installed (patches:"PHCO_32926 PHCO_33488 PHCO_34215 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-64SLIB", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-SHLIBS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-64SLIB", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-SHLIBS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

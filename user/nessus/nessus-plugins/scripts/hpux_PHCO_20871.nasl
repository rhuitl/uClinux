#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16913);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHCO_20871";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_20871 .
(Sec. Vulnerability in bdf(1) & df(1) commands)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHCO_20871
See also : HPUX security bulletin 127
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_20871";
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

if ( ! hpux_check_ctx ( ctx:"800:10.26 700:10.26 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_20871 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CMDS-AUX", version:NULL) )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16548);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHCO_21567";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_21567 .
(Sec. Vulnerability with shutdown command)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHCO_21567
See also : HPUX security bulletin 113
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_21567";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_21567 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.UX-CORE", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}

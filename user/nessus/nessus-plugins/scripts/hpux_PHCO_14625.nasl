#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17370);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHCO_14625";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_14625 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_14625
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_14625";
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

if ( hpux_patch_installed (patches:"PHCO_14625 PHCO_19945 PHCO_22274 PHCO_23117 PHCO_28630 PHCO_33021 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CMDS-AUX", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}

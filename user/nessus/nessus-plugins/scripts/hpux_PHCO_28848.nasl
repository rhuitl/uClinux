#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16981);
 script_version ("$Revision: 1.6 $");

 name["english"] = "HP-UX Security patch : PHCO_28848";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_28848 .
(SSRT061134 rev.1 - HP-UX Running swagentd Remote Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_28848
See also : HPUX security bulletin 2105
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_28848";
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

if ( hpux_patch_installed (patches:"PHCO_28848 PHCO_32116 PHCO_33822 PHCO_34295 PHCO_34539 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0106") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0109") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0112") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0203") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0206") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0209") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0212") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0303") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0306") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-AGENT", version:"B.11.11.0309") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0106") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0109") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0112") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0203") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0206") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0209") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0212") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0303") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0306") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-CMDS", version:"B.11.11.0309") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0106") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0109") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0112") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0203") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0206") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0209") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0212") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0303") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0306") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-HELP", version:"B.11.11.0309") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0106") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0109") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0112") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0203") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0206") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0209") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0212") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0303") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0306") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0309") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0106") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0109") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0112") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0203") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0206") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0209") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0212") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0303") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0306") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0309") )
{
 security_hole(0);
 exit(0);
}

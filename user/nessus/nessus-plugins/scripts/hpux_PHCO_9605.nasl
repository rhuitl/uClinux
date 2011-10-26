#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16942);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHCO_9605";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_9605 .
(Security Vulnerability in newgrp executable)

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/10.X/PHCO_9605
See also : HPUX security bulletin 048
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_9605";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 700:10.10 800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_9605 PHCO_12098 PHCO_12098 PHCO_12097 PHCO_12097 PHCO_12098 PHCO_12098 PHCO_12097 PHCO_12097 PHCO_12098 PHCO_12098 PHCO_12097 PHCO_12097 PHCO_12098 PHCO_12098 PHCO_12097 PHCO_12097 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CMDS-AUX", version:NULL) )
{
 security_hole(0);
 exit(0);
}

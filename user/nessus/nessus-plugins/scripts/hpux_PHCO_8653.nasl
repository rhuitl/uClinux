#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16691);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHCO_8653";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_8653 .
(Vulnerability in /usr/lib/expreserve)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHCO_8653
See also : HPUX security bulletin 033
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_8653";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 700:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_8653 PHCO_9489 PHCO_11881 PHCO_12334 PHCO_13653 PHCO_22848 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"TextEditors.EDITORS", version:NULL) )
{
 security_hole(0);
 exit(0);
}

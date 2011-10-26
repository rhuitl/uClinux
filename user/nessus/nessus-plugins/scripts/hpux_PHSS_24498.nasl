#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16687);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_24498";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24498 .
(Security Vulnerability in ecsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_24498
See also : HPUX security bulletin 158
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24498";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_24498 PHSS_25944 PHSS_26909 PHSS_28650 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVECS.OVECS-DES", version:"A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-DM", version:"A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-PRG-TI", version:"A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-PRG", version:"A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN", version:"A.03.00") )
{
 security_hole(0);
 exit(0);
}

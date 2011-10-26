#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18349);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_32918";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_32918 .
(SSRT4796, SSRT4873 rev.0 - OpenView Event Correlation Services (OV ECS) Remote Unauthorized Privileged Code Execution, Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_32918
See also : HPUX security bulletin 1141
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_32918";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.11 700:11.11 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_32918 PHSS_33538 PHSS_34634 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVECS.OVECS-CMG", version:"A.03.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-CMG", version:"A.03.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN", version:"A.03.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN", version:"A.03.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN-JPN", version:"A.03.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN-JPN", version:"A.03.32") )
{
 security_hole(0);
 exit(0);
}

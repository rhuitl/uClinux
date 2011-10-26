#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16688);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_24497";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24497 .
(Security Vulnerability in ecsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_24497
See also : HPUX security bulletin 158
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24497";
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

if ( hpux_patch_installed (patches:"PHSS_24497 PHSS_25943 PHSS_26908 PHSS_28649 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVECS.OVECS-DES", version:"	OVECS.OVECS-DES,A.03.00 OVECS.OVECS-DM,A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-PRG-TI", version:"	OVECS.OVECS-PRG-TI,A.03.00 OVECS.OVECS-PRG,A.03.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVECS.OVECS-RUN", version:"	OVECS.OVECS-RUN,A.03.00") )
{
 security_hole(0);
 exit(0);
}

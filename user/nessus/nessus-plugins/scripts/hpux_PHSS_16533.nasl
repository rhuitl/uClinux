#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17443);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_16533";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_16533 .
(Security Vulnerability with HP OpenView Omniback II)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_16533
See also : HPUX security bulletin 085
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_16533";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 800:10.00 700:10.00 800:10.10 700:10.10 800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_16533 PHSS_17309 PHSS_21636 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OMNIBACK-II.OMNI-WIN-P", version:NULL) )
{
 security_hole(0);
 exit(0);
}

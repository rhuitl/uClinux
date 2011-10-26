#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16638);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHCO_24701";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_24701 .
(Sec. Vulnerability in rlpdaemon)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_24701
See also : HPUX security bulletin 163
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_24701";
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

if ( hpux_patch_installed (patches:"PHCO_24701 PHCO_25111 PHCO_27020 PHCO_28259 PHCO_29209 PHCO_30431 PHCO_31106 PHCO_32222 PHCO_33401 PHCO_34822 PHCO_34993 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"PrinterMgmt.LP-SPOOL", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

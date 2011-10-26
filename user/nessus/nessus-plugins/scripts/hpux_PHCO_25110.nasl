#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16958);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHCO_25110";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_25110 .
(Sec. Vulnerability in rlpdaemon)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_25110
See also : HPUX security bulletin 176
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_25110";
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

if ( hpux_patch_installed (patches:"PHCO_25110 PHCO_27132 PHCO_28320 PHCO_29208 PHCO_31016 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"PrinterMgmt.LP-SPOOL", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}

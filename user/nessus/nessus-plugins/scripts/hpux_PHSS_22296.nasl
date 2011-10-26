#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16870);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_22296";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_22296 .
(Sec. Vulnerability in VVOS NSAPI)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_22296
See also : HPUX security bulletin 124
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_22296";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_22296 PHSS_23526 PHSS_24836 PHSS_25208 PHSS_25435 PHSS_25662 PHSS_27262 PHSS_27499 PHSS_28198 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultNES.NES-VAULT", version:"A.04.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-CORE-CMN", version:"A.04.00") )
{
 security_hole(0);
 exit(0);
}

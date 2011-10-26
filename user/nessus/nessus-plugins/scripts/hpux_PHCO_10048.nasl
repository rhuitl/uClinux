#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16889);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHCO_10048";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHCO_10048 .
(Security Vulnerability in vgdisplay command)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHCO_10048
See also : HPUX security bulletin 056
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHCO_10048";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_10048 PHCO_10964 PHCO_12666 PHCO_13224 PHCO_13480 PHCO_13711 PHCO_13942 PHCO_14315 PHCO_14628 PHCO_14990 PHCO_15236 PHCO_15895 PHCO_16049 PHCO_17118 PHCO_17389 PHCO_18563 PHCO_23437 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"LVM.LVM-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"LVM.LVM-ENG-A-MAN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

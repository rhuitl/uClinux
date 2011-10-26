#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16630);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_28444";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_28444 .
(SSRT3585 Potential Security Vulnerability in PHNE_26413 and PHNE_27128 (rev.2))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_28444
See also : HPUX security bulletin 270
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_28444";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_28444 PHNE_30450 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NETTL-MIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NETTL-RUN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NETTL-ADM", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NW-ENG-A-MAN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NETTL-64SLIB", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

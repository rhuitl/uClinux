#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16604);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHNE_28536";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_28536 .
(SSRT3451 Potential Security Vulnerability in HP-UX network drivers (Data Leakage) (rev. 01))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s800/10.X/PHNE_28536
See also : HPUX security bulletin 261
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_28536";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_28536 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Networking.LAN-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.LAN-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NW-ENG-A-MAN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

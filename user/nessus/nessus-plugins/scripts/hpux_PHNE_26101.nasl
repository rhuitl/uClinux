#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16827);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHNE_26101";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_26101 .
(RFC 1948 ISN randomization is now available (rev.1))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_26101
See also : HPUX security bulletin 205
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_26101";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_26101 PHNE_29453 PHNE_30905 PHNE_33427 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET-PRG", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET-RUN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NMS2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NMS2-KRN", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}

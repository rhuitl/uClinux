#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16713);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHNE_26988";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_26988 .
(Sec. Vulnerability in ASUnetbios)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHNE_26988
See also : HPUX security bulletin 198
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_26988";
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

if ( hpux_patch_installed (patches:"PHNE_26988 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"RFC-NETBIOS.RFC-NETBIOS", version:"B.04.07") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"RFC-NETBIOS.RFC-NETBIOS", version:"B.04.06") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"RFC-NETBIOS.RFC-NETBIOS", version:"B.04.05") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"RFC-NETBIOS.RFC-NETBIOS", version:"B.04.07") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"RFC-NETBIOS.RFC-NETBIOS", version:"B.04.06") )
{
 security_hole(0);
 exit(0);
}

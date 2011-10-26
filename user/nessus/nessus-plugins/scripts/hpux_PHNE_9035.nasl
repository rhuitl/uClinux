#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17058);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_9035";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_9035 .
(Vulnerability with incoming ICMP Echo Request (ping) packets)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHNE_9035
See also : HPUX security bulletin 040
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_9035";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_9035 PHNE_9105 PHNE_10485 PHNE_10961 PHNE_11986 PHNE_12906 PHNE_13470 PHNE_16472 PHNE_19935 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Networking.NET-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

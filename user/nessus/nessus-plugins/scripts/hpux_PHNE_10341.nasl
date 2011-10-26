#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17050);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHNE_10341";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_10341 .
(Security Vulnerability in Novell Netware 3.12 on HP-UX)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHNE_10341
See also : HPUX security bulletin 068
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_10341";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_10341 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"NetWareStack.NETWAREIPX-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NetWareStack.NETWAREIPX-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NetWare312.NetWare312-BIN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NetWare312.NetWare312-ETC", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NetWare312.NetWare312-SYS", version:NULL) )
{
 security_hole(0);
 exit(0);
}

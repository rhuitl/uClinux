#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16562);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_26367";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_26367 .
(Sec. Vulnerability in SNMP (rev. 16))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_26367
See also : HPUX security bulletin 184
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_26367";
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

if ( ! hpux_check_ctx ( ctx:"800:10.24 700:10.24 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_26367 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Networking.MASTER", version:"	Networking.MASTER,B.10.24 Networking.SUBAGT-MIB2,B.10.24") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.SUBAGT-HPUNIX", version:"	Networking.SUBAGT-HPUNIX,B.10.24") )
{
 security_hole(0);
 exit(0);
}

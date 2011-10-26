#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21552);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_34544";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_34544 .
(SSRT061110 rev.1 - HP-UX Running wu-ftpd Remote Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHNE_34544
See also : HPUX security bulletin 2110
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_34544";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_34544 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

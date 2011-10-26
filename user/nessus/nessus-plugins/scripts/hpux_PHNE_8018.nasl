#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16832);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHNE_8018";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_8018 .
(Security Vulnerability in rpc.pcnfsd & rpc.statd)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700/10.X/PHNE_8018
See also : HPUX security bulletin 032
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_8018";
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

if ( ! hpux_check_ctx ( ctx:"700:10.09 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_8018 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"NFS.NFS-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}

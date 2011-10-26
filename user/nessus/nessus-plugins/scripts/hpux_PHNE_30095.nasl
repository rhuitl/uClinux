#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16724);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_30095";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_30095 .
(SSRT4688 rev.0 HP-UX rpc.ypupdated remote unauth. access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_30095
See also : HPUX security bulletin 1002
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_30095";
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

if ( ! hpux_check_ctx ( ctx:"800:11.23 700:11.23 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_30095 PHKL_31500 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"NFS.NFS-ENG-A-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NIS2-CLIENT", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NIS2-SERVER", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NISPLUS2-CORE", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}

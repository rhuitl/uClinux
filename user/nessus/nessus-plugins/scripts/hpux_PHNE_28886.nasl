#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16570);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHNE_28886";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_28886 .
(SSRT2330 Rev.2 rpc.yppasswdd)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHNE_28886
See also : HPUX security bulletin 242
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_28886";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_28886 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE-ENG-A-MAN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.UX-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-SERVER", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-CLIENT", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NIS-CLIENT", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NIS-SERVER", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-ENG-A-MAN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

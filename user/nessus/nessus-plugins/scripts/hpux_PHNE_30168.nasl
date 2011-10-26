#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17421);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_30168";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_30168 .
(SSRT2439 rev.12 HP-UX xdrmem_getbytes())

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_30168
See also : HPUX security bulletin 252
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_30168";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_30168 PHNE_30808 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"NFS.NFS-CLIENT", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-CORE", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-SHLIBS", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"NFS.NFS-64SLIB", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}

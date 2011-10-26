#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17390);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_12008";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_12008 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHKL_12008
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_12008";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_12008 PHKL_12340 PHKL_17717 PHKL_18198 PHKL_19540 PHKL_21595 PHKL_26981 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"JournalFS.VXFS-BASE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

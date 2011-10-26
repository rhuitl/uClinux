#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17053);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHKL_27832";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_27832 .
(SSRT2358 Security Vulnerability in JFS 3.1)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700/10.X/PHKL_27832
See also : HPUX security bulletin 223
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_27832";
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

if ( ! hpux_check_ctx ( ctx:"700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_27832 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"JournalFS.VXFS-BASE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

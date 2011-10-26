#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16997);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_24201";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_24201 .
(SSRT2358 Security Vulnerability in JFS 3.1)

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/11.X/PHKL_24201
See also : HPUX security bulletin 223
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_24201";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_24201 PHKL_26794 PHKL_27070 PHKL_27648 PHKL_28105 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"JournalFS.VXFS-BASE-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"JournalFS.VXFS-BASE-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}

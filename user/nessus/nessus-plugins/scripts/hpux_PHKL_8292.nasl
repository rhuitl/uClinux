#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17403);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_8292";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_8292 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700/10.X/PHKL_8292
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_8292";
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

if ( ! hpux_check_ctx ( ctx:"700:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_8292 PHKL_8393 PHKL_8790 PHKL_8920 PHKL_9073 PHKL_10103 PHKL_10201 PHKL_10270 PHKL_10873 PHKL_10827 PHKL_11121 PHKL_11432 PHKL_11523 PHKL_11850 PHKL_11815 PHKL_11988 PHKL_12061 PHKL_12429 PHKL_12606 PHKL_13153 PHKL_13280 PHKL_13728 PHKL_14222 PHKL_14296 PHKL_14508 PHKL_14556 PHKL_15470 PHKL_15599 PHKL_15885 PHKL_16167 PHKL_19803 PHKL_20532 PHKL_22668 PHKL_23477 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.C-INC", version:NULL) )
{
 security_hole(0);
 exit(0);
}

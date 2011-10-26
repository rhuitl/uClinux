#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17404);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_8293";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_8293 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHKL_8293
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_8293";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_8293 PHKL_8394 PHKL_8713 PHKL_8921 PHKL_9074 PHKL_10104 PHKL_10202 PHKL_10271 PHKL_10874 PHKL_10828 PHKL_11122 PHKL_11433 PHKL_11524 PHKL_11816 PHKL_12062 PHKL_12177 PHKL_12430 PHKL_13154 PHKL_13729 PHKL_14223 PHKL_14297 PHKL_14509 PHKL_14557 PHKL_15471 PHKL_15886 PHKL_16168 PHKL_16409 PHKL_20533 PHKL_23478 ") )
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

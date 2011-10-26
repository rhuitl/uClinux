#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16721);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHKL_23628";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_23628 .
(Sec. Vulnerability in setrlimit(1M) (rev. 1))

Solution : ftp://ftp.itrc.hp.com/patches_with_warnings/hp-ux_patches/s700_800/11.X/PHKL_23628
See also : HPUX security bulletin 156
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_23628";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_23628 PHKL_23812 PHKL_23813 PHKL_23857 PHKL_24015 PHKL_24116 PHKL_24273 PHKL_24457 PHKL_24612 PHKL_24826 PHKL_24971 PHKL_25164 PHKL_25188 PHKL_25210 PHKL_25525 PHKL_25906 PHKL_26800 PHKL_27157 PHKL_27238 PHKL_27364 PHKL_27759 PHKL_27919 PHKL_27994 PHKL_28053 PHKL_28180 PHKL_28766 PHKL_29345 PHKL_29648 PHKL_30190 PHKL_30709 PHKL_31867 PHKL_33500 PHKL_33819 PHKL_34341 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.C-INC", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}

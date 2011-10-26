#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16766);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_22915";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_22915 .
(Sec. Vulnerability in OV OmniBack)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_22915
See also : HPUX security bulletin 142
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_22915";
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

if ( hpux_patch_installed (patches:"PHSS_22915 PHSS_23688 PHSS_24430 PHSS_25820 PHSS_27590 PHSS_28571 PHSS_30826 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OMNIBACK-II.OMNI-CORE-IS", version:"A.03.50") )
{
 security_hole(0);
 exit(0);
}

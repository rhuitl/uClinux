#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16540);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_7753";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_7753 .
(Security Vulnerability in HP VUE3.0)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_7753
See also : HPUX security bulletin 038
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_7753";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 700:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_7753 PHSS_9805 PHSS_13172 PHSS_23356 PHSS_25592 PHSS_26788 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VUE.VUE-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

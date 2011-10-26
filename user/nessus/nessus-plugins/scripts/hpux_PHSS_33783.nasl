#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19825);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_33783";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_33783 .
(SSRT051023 rev.6 - HP OpenView Network Node Manager (OV NNM) Remote Unauthorized Privileged Access)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_33783
See also : HPUX security bulletin 1224
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_33783";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.11 800:11.23 700:11.11 700:11.23 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_33783 PHSS_33875 PHSS_34098 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}

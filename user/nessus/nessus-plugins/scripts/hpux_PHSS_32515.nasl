#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18343);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_32515";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_32515 .
(SSRT4829 rev.0 - OpenView Network Node Manager (OV NNM) remote Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_32515
See also : HPUX security bulletin 1125
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_32515";
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

if ( ! hpux_check_ctx ( ctx:"800:11.23 700:11.23 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_32515 PHSS_32693 PHSS_32817 PHSS_33073 PHSS_33223 PHSS_33345 PHSS_33460 PHSS_33663 PHSS_34099 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWIN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.50.00") )
{
 security_hole(0);
 exit(0);
}

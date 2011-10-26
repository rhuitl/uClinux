#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16599);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_24946";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24946 .
(Sec. Vulnerability in OV NNM)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_24946
See also : HPUX security bulletin 177
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24946";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 800:10.00 700:10.00 800:10.10 700:10.10 800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_24946 PHSS_25127 PHSS_25990 PHSS_26806 PHSS_27652 PHSS_28001 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVNNMgr.OVNNM-RUN", version:"	OVNNMgr.OVNNM-RUN,B.05.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVEVENT-MIN", version:"	OVPlatform.OVEVENT-MIN,B.05.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"	OVPlatform.OVMIN,B.05.01.00 OVPlatform.OVSNMP-MIN,B.05.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWIN", version:"	OVPlatform.OVWIN,B.05.01.00 OVPlatform.OVWWW-EVNT,B.05.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-FW", version:"	OVPlatform.OVWWW-FW,B.05.01.00") )
{
 security_hole(0);
 exit(0);
}

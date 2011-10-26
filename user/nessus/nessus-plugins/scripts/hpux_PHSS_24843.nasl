#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16624);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_24843";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24843 .
(Sec. Vulnerability in OV NNM)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_24843
See also : HPUX security bulletin 177
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24843";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.11 700:11.11 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_24843 PHSS_25088 PHSS_25225 PHSS_25344 PHSS_25350 PHSS_25365 PHSS_25432 PHSS_25595 PHSS_25661 PHSS_25703 PHSS_25743 PHSS_27333 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVPlatform.OVMIN", version:"B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVPlatform.OVWWW-FW", version:"B.06.20.00") )
{
 security_hole(0);
 exit(0);
}

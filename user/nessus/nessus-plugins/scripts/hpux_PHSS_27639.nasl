#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17482);
 script_version ("$Revision: 1.3 $");

 name["english"] = "HP-UX Security patch : PHSS_27639";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_27639 .
(SSRT2332 rev.10 Apache Server Chunk Encoding)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_27639
See also : HPUX security bulletin 197
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_27639";
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

if ( hpux_patch_installed (patches:"PHSS_27639 PHSS_27747 PHSS_27836 PHSS_27917 PHSS_28092 PHSS_28095 PHSS_28258 PHSS_28348 PHSS_28400 PHSS_28473 PHSS_28546 PHSS_28587 PHSS_28705 PHSS_28878 PHSS_29206 PHSS_29429 PHSS_29754 PHSS_30104 PHSS_30419 PHSS_31185 PHSS_32046 PHSS_32690 PHSS_33287 PHSS_34008 PHSS_35113 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVPlatform.OVWWW-SRV", version:"B.06.20.00") )
{
 security_hole(0);
 exit(0);
}

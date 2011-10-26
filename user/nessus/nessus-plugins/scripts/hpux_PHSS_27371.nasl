#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17476);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHSS_27371";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_27371 .
(SSRT2332 rev.10 Apache Server Chunk Encoding)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_27371
See also : HPUX security bulletin 197
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_27371";
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

if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_27371 PHSS_27627 PHSS_28098 PHSS_28685 PHSS_29545 PHSS_29690 PHSS_30160 PHSS_30648 PHSS_31828 PHSS_32184 PHSS_33396 PHSS_34119 PHSS_35107 PHSS_35461 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultWS.WS-CORE", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}

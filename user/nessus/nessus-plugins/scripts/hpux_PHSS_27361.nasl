#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17475);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHSS_27361";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_27361 .
(SSRT2332 rev.10 Apache Server Chunk Encoding)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_27361
See also : HPUX security bulletin 197
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_27361";
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

if ( hpux_patch_installed (patches:"PHSS_27361 PHSS_27476 PHSS_27988 PHSS_28099 PHSS_28686 PHSS_29546 PHSS_29691 PHSS_30154 PHSS_30405 PHSS_30645 PHSS_30947 PHSS_31057 PHSS_31826 PHSS_32183 PHSS_33397 PHSS_34120 PHSS_35108 PHSS_35462 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultWS.WS-CORE", version:"A.04.60") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-CORE-CMN", version:"A.04.60") )
{
 security_hole(0);
 exit(0);
}

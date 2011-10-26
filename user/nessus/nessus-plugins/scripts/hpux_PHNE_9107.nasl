#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17039);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_9107";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_9107 .
(SYN Flooding Security Vulnerability in HP-UX)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHNE_9107
See also : HPUX security bulletin 060
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_9107";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_9107 PHNE_11531 PHNE_12058 PHNE_12408 PHNE_13287 PHNE_13468 PHNE_14492 PHNE_14271 PHNE_14770 PHNE_15582 PHNE_16210 PHNE_17097 PHNE_17730 PHNE_19116 PHNE_19936 PHNE_20834 PHNE_22507 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16978);
 script_version ("$Revision: 1.4 $");

 name["english"] = "HP-UX Security patch : PHNE_27703";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_27703 .
(SSRT2443 Network traffic can cause programs to fail)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_27703
See also : HPUX security bulletin 271
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_27703";
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

if ( ! hpux_check_ctx ( ctx:"800:11.11 700:11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_27703 PHNE_28476 PHNE_29825 PHNE_30367 PHNE_31091 PHNE_33313 PHNE_33729 PHNE_34131 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Streams.STREAMS2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Streams.STREAMS2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Streams.STREAMS-32ALIB", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Streams.STREAMS-MIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Streams.STREAMS-64ALIB", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Streams.STREAMS-64SLIB", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}

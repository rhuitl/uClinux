#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22434);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_34999";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_34999 .
(SSRT051019 rev.1 - HP-UX running X.25 Local Denial of Service (Dos))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHNE_34999
See also : HPUX security bulletin 2126
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_34999";
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

if ( hpux_patch_installed (patches:"PHNE_34999 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-ALIB", version:"B.11.23.03") )
{
 security_hole(0);
 exit(0);
}

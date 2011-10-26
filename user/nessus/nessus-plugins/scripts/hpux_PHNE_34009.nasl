#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22430);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_34009";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_34009 .
(SSRT051019 rev.1 - HP-UX running X.25 Local Denial of Service (Dos))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/11.X/PHNE_34009
See also : HPUX security bulletin 2126
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_34009";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_34009 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.21") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.35") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.7.00.06") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-SNMP", version:"A.11.00.ic23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.8") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.8") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.8") )
{
 security_hole(0);
 exit(0);
}

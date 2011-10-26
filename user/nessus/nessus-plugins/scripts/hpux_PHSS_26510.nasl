#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16542);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_26510";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_26510 .
(Sec. Vulnerability in SNMP (rev. 16))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_26510
See also : HPUX security bulletin 184
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_26510";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 800:10.10 700:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_26510 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Networking.MASTER", version:"	Networking.MASTER,B.10.01 Networking.MASTER,B.10.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.SUBAGT-HPUNIX", version:"	Networking.SUBAGT-HPUNIX,B.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.SUBAGT-HPUNIX", version:"	Networking.SUBAGT-HPUNIX,B.10.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.SUBAGT-MIB2", version:"	Networking.SUBAGT-MIB2,B.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.SUBAGT-MIB2", version:"	Networking.SUBAGT-MIB2,B.10.10 OVSNMPAgent.MASTER,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.10.26.00 OVSNMPAgent.MASTER,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.04.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17472);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_27181";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_27181 .
(Sec. Vulnerability in SNMP (rev. 16))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_27181
See also : HPUX security bulletin 184
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_27181";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_27181 PHSS_27569 PHSS_27849 PHSS_27857 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.10.27.00 OVSNMPAgent.MASTER,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.11.00.00 OVSNMPAgent.MASTER,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16500);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_19739";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_19739 .
(SSRT3608 Potential security vulnerability in DCE)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_19739
See also : HPUX security bulletin 273
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_19739";
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

if ( hpux_patch_installed (patches:"PHSS_19739 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"DCE-C-Tools.DCE-TOOLS-LIB", version:"	DCE-C-Tools.DCE-TOOLS-LIB,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-CDS-Server.CDS-SERVER", version:"	DCE-CDS-Server.CDS-SERVER,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-Core.DCE-CORE-DTS", version:"	DCE-Core.DCE-CORE-DTS,B.10.20 DCE-Core.DCE-CORE-RUN,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-Core.DCE-CORE-SHLIB", version:"	DCE-Core.DCE-CORE-SHLIB,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-Core.DCE-JPN-E-MSG", version:"	DCE-Core.DCE-JPN-E-MSG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-Core.DCE-JPN-S-MSG", version:"	DCE-Core.DCE-JPN-S-MSG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-Core.DCEC-ENG-A-MAN", version:"	DCE-Core.DCEC-ENG-A-MAN,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-CoreAdmin.DCE-ACCT-MGR", version:"	DCE-CoreAdmin.DCE-ACCT-MGR,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-CoreAdmin.DCE-CDSBROWSER", version:"	DCE-CoreAdmin.DCE-CDSBROWSER,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-CoreAdmin.DCE-CORE-DIAG", version:"	DCE-CoreAdmin.DCE-CORE-DIAG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-CoreTools.DCE-BPRG", version:"	DCE-CoreTools.DCE-BPRG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-GDS-Server.GDS-SERVER", version:"	DCE-GDS-Server.GDS-SERVER,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DCE-SEC-Server.SEC-SERVER", version:"	DCE-SEC-Server.SEC-SERVER,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DFS-Core.DFS-CLIENT", version:"	DFS-Core.DFS-CLIENT,B.10.20 DFS-Core.DFS-COMMON,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DFS-Core.DFS-JPN-E-MSG", version:"	DFS-Core.DFS-JPN-E-MSG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DFS-Core.DFS-JPN-S-MSG", version:"	DFS-Core.DFS-JPN-S-MSG,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DFS-NFSgateway.DFS-NFS-SERVER", version:"	DFS-NFSgateway.DFS-NFS-SERVER,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"IntegratedLogin.AUTH-COMMON", version:"	IntegratedLogin.AUTH-COMMON,B.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"IntegratedLogin.AUTH-DCE", version:"	IntegratedLogin.AUTH-DCE,B.10.20") )
{
 security_hole(0);
 exit(0);
}

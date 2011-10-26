#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16824);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_22540";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_22540 .
(Sec. Vulnerability in MC/ServiceGuard)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_22540
See also : HPUX security bulletin 129
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_22540";
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

if ( hpux_patch_installed (patches:"PHSS_22540 PHSS_22683 PHSS_22876 PHSS_23511 PHSS_24033 PHSS_24536 PHSS_24850 PHSS_25499 PHSS_25935 PHSS_26338 PHSS_26750 PHSS_27158 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"DLM.CM-DLM", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM.CM-DLM-CMDS", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Clust-Mon.CM-CORE", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Pkg-Mgr.CM-PKG", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-MOF", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ATS-CORE.ATS-RUN", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}

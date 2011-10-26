#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16488);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_23064";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_23064 .
(Sec. Vulnerability in Support Tools Manager)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700/10.X/PHSS_23064
See also : HPUX security bulletin 137
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_23064";
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

if ( ! hpux_check_ctx ( ctx:"700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_23064 PHSS_23653 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Sup-Tool-Mgr-700.STM-UI-RUN", version:"	Sup-Tool-Mgr-700.STM-UI-RUN,B.10.20.20.08") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Sup-Tool-Mgr-700.STM-CATALOGS", version:"	Sup-Tool-Mgr-700.STM-CATALOGS,B.10.20.20.08") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Sup-Tool-Mgr-700.STM-SHLIBS", version:"	Sup-Tool-Mgr-700.STM-SHLIBS,B.10.20.20.08") )
{
 security_hole(0);
 exit(0);
}

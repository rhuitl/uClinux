#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21735);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHSS_34288";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_34288 .
(SSRT061077 rev.2 - HP-UX running Support Tools Manager (xstm, cstm, stm) Local Denial of Service (DoS))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_34288
See also : HPUX security bulletin 2115
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_34288";
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

if ( hpux_patch_installed (patches:"PHSS_34288 PHSS_34835 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Sup-Tool-Mgr.STM-UUT-RUN", version:"B.11.11.16.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Sup-Tool-Mgr.STM-CATALOGS", version:"B.11.11.16.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Sup-Tool-Mgr.STM-SHLIBS", version:"B.11.11.16.09") )
{
 security_hole(0);
 exit(0);
}

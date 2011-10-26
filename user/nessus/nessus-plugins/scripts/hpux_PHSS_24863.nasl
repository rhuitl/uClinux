#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16623);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_24863";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_24863 .
(Sec. Vulnerability in PRM)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHSS_24863
See also : HPUX security bulletin 165
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_24863";
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

if ( hpux_patch_installed (patches:"PHSS_24863 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Proc-Resrc-Mgr.PRM-RUN", version:"	Proc-Resrc-Mgr.PRM-RUN,C.01.07 PRM-Sw-Lib.PRM-LIB,C.01.07") )
{
 security_hole(0);
 exit(0);
}

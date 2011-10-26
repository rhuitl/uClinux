#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16794);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_15533";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_15533 .
(Security Vulnerability with Predictive on HP-UX)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHSS_15533
See also : HPUX security bulletin 081
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_15533";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_15533 PHSS_16357 PHSS_17494 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.51") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.52") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.53") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.10.54") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.51") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.52") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.53") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.10.54") )
{
 security_hole(0);
 exit(0);
}

#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16793);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_15534";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_15534 .
(Security Vulnerability with Predictive on HP-UX)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHSS_15534
See also : HPUX security bulletin 081
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_15534";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_15534 PHSS_16358 PHSS_16755 PHSS_17495 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.51") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.52") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.53") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.54") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.55") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.56") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.57") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.20.58") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.51") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.52") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.53") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.54") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.55") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.56") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.57") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.20.58") )
{
 security_hole(0);
 exit(0);
}

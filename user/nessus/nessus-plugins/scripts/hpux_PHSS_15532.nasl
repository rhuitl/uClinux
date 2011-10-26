#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16795);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_15532";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_15532 .
(Security Vulnerability with Predictive on HP-UX)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHSS_15532
See also : HPUX security bulletin 081
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_15532";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_15532 PHSS_16356 PHSS_17493 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-RUN", version:"	Predictive.PREDICTIVE-RUN,C.10.01.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Predictive.PREDICTIVE-MAN", version:"	Predictive.PREDICTIVE-MAN,C.10.01.50") )
{
 security_hole(0);
 exit(0);
}

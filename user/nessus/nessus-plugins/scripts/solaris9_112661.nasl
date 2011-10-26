#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13513);
 script_version ("$Revision: 1.7 $");
 name["english"] = "Solaris 9 (sparc) : 112661-10";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112661-10
( IIIM and X Input & Output Method patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112661-10-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112661-10"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112661-10", obsoleted_by:"", package:"JSatsvw SUNWcleu SUNWhkleu SUNWhleu SUNWiiimr SUNWiiimu SUNWj3irt SUNWjxplt SUNWlccom SUNWxi18n SUNWxi18x SUNWxim SUNWximx");

if ( e < 0 ) security_hole(0);

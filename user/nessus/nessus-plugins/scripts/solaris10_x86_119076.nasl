#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20054);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Solaris 10 (i386) : 119076-10";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 119076-10
( ip Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-119076-10-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 119076-10"; 
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

e =  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119076-10", obsoleted_by:"119076-12", package:"SUNWckr SUNWhea");

if ( e < 0 ) security_hole(0);

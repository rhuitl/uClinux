#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14303);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Solaris 9 (sparc) : 117171-11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 117171-11
( Kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-117171-11-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 117171-11"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"117171-11", obsoleted_by:"112233-12", package:"FJSVhea SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpc.u SUNWcpc.us SUNWcpcx.u SUNWcpcx.us SUNWcsr SUNWcsu SUNWcsxu SUNWhea");

if ( e < 0 ) security_hole(0);

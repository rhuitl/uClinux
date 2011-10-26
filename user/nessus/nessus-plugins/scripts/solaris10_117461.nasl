#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19214);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Solaris 10 (sparc) : 117461-08";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 117461-08
( ld Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-117461-08-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 117461-08"; 
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

e =  solaris_check_patch(release:"5.10", arch:"sparc", patch:"117461-08", obsoleted_by:"118833-17", package:"SUNWbtool SUNWcsl SUNWcslr SUNWcsr SUNWcsu SUNWesu SUNWhea SUNWtoo SUNWxcu4");

if ( e < 0 ) security_hole(0);

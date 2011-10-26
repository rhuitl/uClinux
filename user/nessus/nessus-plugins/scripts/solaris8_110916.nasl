#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13357);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Solaris 8 (sparc) : 110916-06";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 110916-06
( sort patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-110916-06-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 110916-06"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110916-06", obsoleted_by:"", package:"SUNWesu SUNWesxu SUNWxcu4");

if ( e < 0 ) security_hole(0);

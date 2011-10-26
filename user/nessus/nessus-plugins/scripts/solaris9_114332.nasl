#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13552);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(10594, 9852);
 name["english"] = "Solaris 9 (sparc) : 114332-23";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 114332-23
( c2audit & *libbsm.so.1 Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-114332-23-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 114332-23"; 
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

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"114332-23", obsoleted_by:"", package:"SUNWarc SUNWcarx.u SUNWcarx.us SUNWcsl SUNWcslx SUNWcsr SUNWcstl SUNWcstlx SUNWcsu SUNWcsxu SUNWhea SUNWvolr");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10594", value:TRUE);
	set_kb_item(name:"BID-9852", value:TRUE);
}

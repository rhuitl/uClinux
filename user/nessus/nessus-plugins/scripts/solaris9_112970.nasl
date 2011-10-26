#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13528);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(6159, 6160, 6161, 9114);
 name["english"] = "Solaris 9 (sparc) : 112970-09";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112970-09
( patch libresolv).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112970-09-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112970-09"; 
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

e =  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112970-09", obsoleted_by:"", package:"SUNWarc SUNWarcx SUNWcsl SUNWcslx SUNWcstl SUNWcstlx SUNWcsu SUNWhea SUNWinamd");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-6159", value:TRUE);
	set_kb_item(name:"BID-6160", value:TRUE);
	set_kb_item(name:"BID-6161", value:TRUE);
	set_kb_item(name:"BID-9114", value:TRUE);
}

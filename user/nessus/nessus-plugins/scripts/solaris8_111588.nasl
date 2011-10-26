#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13376);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(13752);
 name["english"] = "Solaris 8 (sparc) : 111588-07";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 111588-07
( /kernel/drv/ws and /kernel/fs/specfs patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-111588-07-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 111588-07"; 
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

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"111588-07", obsoleted_by:"", package:"SUNWcarx.u SUNWcarx.us SUNWcsr SUNWhea");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-13752", value:TRUE);
}

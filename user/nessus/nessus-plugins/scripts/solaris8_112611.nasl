#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13391);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(4267, 6913);
 script_cve_id("CVE-2002-0059", "CVE-2003-0107");
 name["english"] = "Solaris 8 (sparc) : 112611-02";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112611-02
( /usr/lib/libz.so.1 patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112611-02-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112611-02"; 
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

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"112611-02", obsoleted_by:"", package:"SUNWzlib SUNWzlibx");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"CVE-2002-0059", value:TRUE);
	set_kb_item(name:"CVE-2003-0107", value:TRUE);
	set_kb_item(name:"BID-4267", value:TRUE);
	set_kb_item(name:"BID-6913", value:TRUE);
}

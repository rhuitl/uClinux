#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13407);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(10202, 5171, 6309, 8250, 8314, 8831, 8929, 9477, 9962);
 name["english"] = "Solaris 8 (i386) : 108529-29";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 108529-29
( Supplement Kernel Update Patch for 108529-16).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-108529-29-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 108529-29"; 
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

e =  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108529-29", obsoleted_by:"108529-17", package:"SUNWapchS SUNWapchd SUNWapchr SUNWapchu SUNWarc SUNWcar.i SUNWcpc.i SUNWcsl SUNWcsr SUNWcstl SUNWcsu SUNWhea SUNWmdb SUNWncar SUNWncau SUNWos86r SUNWpmr SUNWpmu SUNWscpu SUNWsrh SUNWtnfc");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10202", value:TRUE);
	set_kb_item(name:"BID-5171", value:TRUE);
	set_kb_item(name:"BID-6309", value:TRUE);
	set_kb_item(name:"BID-8250", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-8929", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}

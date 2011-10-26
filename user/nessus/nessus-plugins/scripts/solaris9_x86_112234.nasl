#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13578);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(10202, 10216, 6309, 8314, 9477, 9962);
 name["english"] = "Solaris 9 (i386) : 112234-12";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112234-12
( Kernel Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112234-12-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112234-12"; 
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

e =  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112234-12", obsoleted_by:"", package:"SUNWarc SUNWcar.i SUNWcpc.i SUNWcsl SUNWcsr SUNWcstl SUNWcsu SUNWfss SUNWhea SUNWkvm.i SUNWmdb SUNWncar SUNWnfscr SUNWnisu SUNWos86r SUNWpmu SUNWrmodr");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10202", value:TRUE);
	set_kb_item(name:"BID-10216", value:TRUE);
	set_kb_item(name:"BID-6309", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}

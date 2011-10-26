#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14366);
 script_bugtraq_id(10911);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Solaris 9 (i386) : 112786-32";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112786-32
(XDMCP DoS).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/pub-cgi/findPatch.pl?patchId=112786&rev=32
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112786-32"; 
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

e =  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112786-32", obsoleted_by:"", package:"SUNWxwfnt SUNWxwinc SUNWxwman SUNWxwopt SUNWxwplt SUNWxwpmn SUNWxwslb SUNWxwsrv");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10911", value:TRUE);
}

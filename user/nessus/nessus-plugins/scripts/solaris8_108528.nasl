#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13295);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(10202, 8054, 8079, 8250, 8314, 8831, 8929, 9477, 9962);
 name["english"] = "Solaris 8 (sparc) : 108528-29";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 108528-29
( kernel update  and Apache patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-108528-29-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 108528-29"; 
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

e =  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVhea FJSVmdb FJSVmdbx FJSVpiclu FJSVvplr.us FJSVvplu.us SUNWapchS SUNWapchd SUNWapchr SUNWapchu SUNWarc SUNWarcx SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpc.u SUNWcpc.us SUNWcpcx.u SUNWcpcx.us SUNWcpr.m SUNWcpr.u SUNWcpr.us SUNWcprx.u SUNWcprx.us SUNWcsl SUNWcslx SUNWcsr SUNWcstl SUNWcstlx SUNWcsu SUNWcsxu SUNWdrr.u SUNWdrr.us SUNWdrrx.u SUNWdrrx.us SUNWefcx.u SUNWfruid SUNWfruip.u SUNWfruix SUNWhea SUNWidn.u SUNWidnx.u SUNWkvm.u SUNWkvm.us SUNWkvmx.u SUNWkvmx.us SUNWmdb SUNWmdbx SUNWncar SUNWncarx SUNWncau SUNWncaux SUNWpiclh SUNWpiclu SUNWpiclx SUNWpmr SUNWpmu SUNWpmux SUNWscpu SUNWsrh SUNWtnfc SUNWtnfcx SUNWusx.u SUNWwrsdx.u SUNWwrsmx.u SUNWwrsux.u");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10202", value:TRUE);
	set_kb_item(name:"BID-8054", value:TRUE);
	set_kb_item(name:"BID-8079", value:TRUE);
	set_kb_item(name:"BID-8250", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-8929", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}

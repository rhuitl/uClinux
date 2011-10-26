#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13086);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(10594, 5986, 7820, 8079, 8314, 8831, 8929, 9477, 9962);
 name["english"] = "Solaris 7 (sparc) : 106541-42";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 106541-42
( Kernel Update Patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-106541-42-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 106541-42"; 
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

e =  solaris_check_patch(release:"5.7", arch:"sparc", patch:"106541-42", obsoleted_by:"", package:"FJSVhea SUNWarc SUNWarcx SUNWatfsr SUNWcar.c SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.us SUNWcarx.u SUNWcarx.us SUNWcpr.m SUNWcpr.u SUNWcpr.us SUNWcprx.u SUNWcprx.us SUNWcsl SUNWcslx SUNWcsr SUNWcsu SUNWcsxu SUNWcvc.u SUNWcvcx.u SUNWdpl SUNWdplx SUNWdrr.u SUNWdrrx.u SUNWesu SUNWesxu SUNWhea SUNWipc SUNWkvm.c SUNWkvm.d SUNWkvm.m SUNWkvm.u SUNWkvm.us SUNWkvmx.u SUNWkvmx.us SUNWnisu SUNWpcmci SUNWpcmcu SUNWpcmcx SUNWscpu SUNWscpux SUNWssad SUNWssadx SUNWsxr.m SUNWtnfc SUNWtnfcx SUNWtoo SUNWtoox SUNWvolr SUNWvolu SUNWypu");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-10594", value:TRUE);
	set_kb_item(name:"BID-5986", value:TRUE);
	set_kb_item(name:"BID-7820", value:TRUE);
	set_kb_item(name:"BID-8079", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-8929", value:TRUE);
	set_kb_item(name:"BID-9477", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}

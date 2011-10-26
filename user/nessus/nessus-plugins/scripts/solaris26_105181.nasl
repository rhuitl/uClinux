#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12863);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(5161, 6309, 6535, 8314, 8831, 9962);
 name["english"] = "Solaris 2.6 (sparc) : 105181-39";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 105181-39
( Kernel update patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-105181-39-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 105181-39"; 
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

e =  solaris_check_patch(release:"5.6", arch:"sparc", patch:"105181-39", obsoleted_by:"", package:"FJSVhea SUNWarc SUNWcar.c SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.u1 SUNWcar.us SUNWcg6.c SUNWcg6.d SUNWcg6.m SUNWcg6.u SUNWcg6.us SUNWcsd SUNWcsr SUNWcsu SUNWdrr.u1 SUNWhea SUNWhmd SUNWhmdu SUNWkvm.u SUNWkvm.u1 SUNWkvm.us SUNWnisu SUNWsrh SUNWssadv SUNWssaop");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-5161", value:TRUE);
	set_kb_item(name:"BID-6309", value:TRUE);
	set_kb_item(name:"BID-6535", value:TRUE);
	set_kb_item(name:"BID-8314", value:TRUE);
	set_kb_item(name:"BID-8831", value:TRUE);
	set_kb_item(name:"BID-9962", value:TRUE);
}

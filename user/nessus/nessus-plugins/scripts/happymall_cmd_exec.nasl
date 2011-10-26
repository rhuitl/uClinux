#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0058.html

 desc = "
The remote host is running the HappyMall E-Commerce CGI suite.

There is a flaw in this suite which allows an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	/shop/normal_html.cgi?file=|id|


Solution : Upgrade to the newest version of this CGI
Risk factor : High";


if(description)
{
 script_id(11602);
 script_bugtraq_id(7529, 7530);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0243");
 
 name["english"] = "HappyMall Command Execution";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for HappyMall";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			extra_dirs:make_list("/shop"),
			check_request:"/normal_html.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

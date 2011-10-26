#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc = "The KW whois cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : remove it from /cgi-bin or upgrade to version 1.1

Risk factor : High";


if(description)
{
 script_id(10541);
 script_bugtraq_id(1883);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0941");

 name["english"] = "KW whois";
 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Checks for the presence of /cgi-bin/whois.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			check_request:"/whois.cgi?action=load&whois=%3Bid",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

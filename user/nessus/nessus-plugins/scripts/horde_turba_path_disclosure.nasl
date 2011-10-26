#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: 17 May 2003 13:18:59 -0000
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com
#  Subject: Path Disclosure in Turba of Horde
#
#

if (description)
{
 script_id(11646);
 script_version ("$Revision: 1.7 $");

 script_bugtraq_id(7622);

 script_name(english:"Turba Path Disclosure");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from an
information disclosure vulnerability.

Description :

There is a flaw in the file 'status.php' of this CGI which may allow
an attacker to retrieve the physical path of the remote web root. 

See also :

http://www.securityfocus.com/archive/1/321823

Solution : 

Properly set the PHP options 'display_errors' and 'log_errors' to
avoid having PHP display its errors on the web pages it produces. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Checks for status.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 script_dependencies("horde_turba_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde_turba"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 url = string(d, '/status.php');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
    egrep(pattern:"/status.php3? on line", string:buf))
   {
    security_note(port);
   }
}

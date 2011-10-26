#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# Basit cms Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

if (description)
{
 script_id(11445);
 script_bugtraq_id(7139);
 script_version ("$Revision: 1.15 $");

 script_name(english:"Basit cms Cross Site Scripting Bugs");
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script which is vulnerable to a 
cross site scripting and SQL injection issue.

Description :

Basit cms  1.0 has a cross site scripting bug. An attacker may use it to
perform a cross site scripting attack on this host.

In addition to this, it is vulnerable to a SQL insertion
attack which may allow an attacker to get the control
of your database.

Solution : 

Upgrade to a newer version.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Basit cms is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 k-otik.com");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs());



foreach d (dir)
{
 url = string(d, "/modules/Submit/index.php?op=pre&title=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_note(port);
    exit(0);
   }
}


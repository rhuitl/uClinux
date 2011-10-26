#
#  Written by K-Otik.com <ReYn0@k-otik.com>
#
#  Mambo Site Server 4.0.10 XSS attack
#
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <ertank@olympos.org> 
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns </archive/1/315554/2003-03-19/2003-03-25/1>
#

if (description)
{
 script_id(11441);
 script_cve_id("CVE-2003-1203");
 script_bugtraq_id(7135);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"7493");
 script_version ("$Revision: 1.14 $");

 script_name(english:"Mambo Site Server 4.0.10 XSS");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a cross-
site scripting attack. 

Description :

An attacker may use the installed version of Mambo Site Server to
perform a cross-site scripting attack on this host. 

See also :

http://www.securityfocus.com/archive/1/315554

Solution: 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 k-otik.com");
 script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/index.php?option=search&searchword=<script>alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( "<script>alert(document.cookie);</script>" >< buf)
    security_note(port);
}

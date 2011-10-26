#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# Siteframe Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

if (description)
{
 script_id(11448);
 script_bugtraq_id(7140, 7143);
 script_version ("$Revision: 1.13 $");

 script_name(english:"Siteframe Cross Site Scripting Bugs");
 desc["english"] = "
Siteframe 2.2.4  has a cross site scripting bug. An attacker may use it to
perform a cross site scripting attack on this host.

In addition to this, another flaw in this package may allow an attacker to
obtain the physical path to the remote web root.

Solution : Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Siteframe is vulnerable to xss attack");
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
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


foreach d (cgi_dirs())
{
 url = string(d, "/search.php?searchfor=", raw_string(0x22), "><script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}


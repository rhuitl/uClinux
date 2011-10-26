#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# osCommerce Cross Site Scripting Bugs
#
# Ref (added by rd) :
#  Message-ID: <009e01c2eef9$069683b0$0900a8c0@compcaw8>
#  From: Daniel Alcántara de la Hoz <seguridad@iproyectos.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: [IPS] osCommerce multiple XSS vulnerabilities
#

if (description)
{
 script_id(11437);
 script_bugtraq_id(7151, 7153, 7155, 7156, 7158);
 script_version ("$Revision: 1.11 $");

 script_name(english:"osCommerce Cross Site Scripting Bugs");
 desc["english"] = "
osCommerce is a widely installed open source shopping e-commerce solution.
An attacker may use it to perform a cross site scripting attack on
this host.

Solution : Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if osCommerce is vulnerable to xss attack");
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
if(!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());



foreach d (dir)
{
 url = string(d, "/default.php?error_message=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
    "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}

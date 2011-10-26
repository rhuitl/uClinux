#
# (C) Tenable Network Security
#

if (description)
{
 script_id(11610);
 script_bugtraq_id(7214);
 script_version ("$Revision: 1.6 $");

 script_name(english:"testcgi.exe Cross Site Scripting");
 desc["english"] = "
The remote host has a CGI called 'testcgi.exe' installed
under /cgi-bin which is vulnerable to a cross site scripting
issue.


Solution: Upgrade to a newer version.
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if testcgi.exe is vulnerable to xss");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs());
		


foreach d (dir)
{
 url = string(d, '/testcgi.exe?<script>x</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>x</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}

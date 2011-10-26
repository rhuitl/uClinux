#
# (C) Tenable Network Security
#

if (description)
{
 script_id(18048);
 script_cve_id("CVE-2005-1135");
 script_bugtraq_id(13170);
 script_version ("$Revision: 1.4 $");

 script_name(english:"sphpblog Cross Site Scripting Vulnerability");
 desc["english"] = "
The remote host is running sphpblog, an open source blog application
written in PHP.

Due to a lack of input validation bug, the remote version of this software can
be used to perform a cross site scripting attack. 

Solution : Upgrade to a newer version or disable this software.
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if sphpblob is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("cross_site_scripting.nasl");
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
 url = string(d, "/search.php?q=<script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if("<b><script>foo</script></b>" >< buf )
   {
    security_warning(port:port);
    exit(0);
   }
}

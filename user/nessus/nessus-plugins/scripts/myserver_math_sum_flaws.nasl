#
# (C) Tenable Network Security
#

if (description)
{
 script_id(14182);
 script_bugtraq_id(10831);
 script_version ("$Revision: 1.3 $");

 script_name(english:"myServer math_sum.mscgi multiple flaws");
 desc["english"] = "
The sample CGI math_sum.mscgi is installed on the remote web server.

The remote version of this CGI contain several issues which may allow
an attacker to execute a cross site scripting attack, to disable the
remote server remotely or to execute arbitrary code with the privileges of the
server.

Solution : Delete math_sum.mscgi
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if math_sum.cgi is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


foreach d (cgi_dirs())
{
 url = string(d, "/math_sum.mscgi");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
  if("<title>MyServer</title>" >< buf )
   {
    url = string(d, "/math_sum.mscgi?a=<script>foo</script>&b=");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if ( ! buf ) exit(0);
    if ( "<script>foo</script>" >< buf )
	{
	 security_hole(port);
	 exit(0);
	}
   }
}


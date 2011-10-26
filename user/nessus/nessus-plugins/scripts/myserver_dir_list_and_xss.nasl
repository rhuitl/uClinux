#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Dr_insane
#
#  This script is released under the GNU GPL v2
#

if (description)
{
 script_id(18218);
 script_bugtraq_id(13579, 13578);
 script_version ("$Revision: 1.3 $");

 script_name(english:"myServer Directory Listing and XSS flaws");
 desc["english"] = "
The remote host is running myServer, an open-source http server.
This version is vulnerable to a directory listing flaw and XSS.

An attacker can execute a cross site scripting attack, 
or gain knowledge of certain system information of the
server.

Solution : Upgrade to version 0.8.1 when available
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if myServer is vulnerable to a XSS flaw");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
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

buf = http_get_cache(item:"/", port:port);
if( buf == NULL ) exit(0);

foreach d (cgi_dirs())
{
  if("<title>MyServer</title>" >< buf )
   {
    url = string(d, '/.../.../"onmouseover="<script>foo</script>"');
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if ( ! buf ) exit(0);
    if ( "<script>foo</script>" >< buf )
	{
	 security_warning(port);
	 exit(0);
	}
   }
}


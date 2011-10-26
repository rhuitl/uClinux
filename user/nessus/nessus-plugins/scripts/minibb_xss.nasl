#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11972);
 script_bugtraq_id(9310);
 script_version ("$Revision: 1.7 $");

 script_name(english:"miniBB cross site scripting");
 desc["english"] = "
The remote host is using the miniBB forum management system.

According to its version number, this forum is vulnerable to a
cross site scripting bug which may allow an attacker with a valid account
to execute embed malicious HTML commands in the site.

Solution: none at this time
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary commands");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (cgi_dirs())
{
 url = string(d, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 str = egrep(pattern:"Powered by.*miniBB", string:buf);
 if( str )
   {
    version = ereg_replace(pattern:".*Powered by.*miniBB (.*)</a>.*", string:str, replace:"\1");
    if ( d == "" ) d = "/";

    set_kb_item(name:"www/" + port + "/minibb", value:version + " under " + d);

    if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7[^a-z])", string:version) )
     {
     security_warning(port);
     exit(0);
     }
   }
}

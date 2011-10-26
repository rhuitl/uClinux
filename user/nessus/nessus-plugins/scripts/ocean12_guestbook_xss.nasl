#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
#  From: "drG4njubas" <drG4nj@mail.ru>
#  To: <bugtraq@securityfocus.com>
#  Subject: Ocean12 ASP Guestbook Manager v1.00
#  Date: Fri, 11 Apr 2003 16:29:16 +0400


if(description)
{
 script_id(11537);
 script_bugtraq_id(7329);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "Ocean12 Guestbook XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Ocean12 GuestBook, a set of scripts
to manage an interactive guestbook.

An attacker may use this module to inject malicious HTML code in your
site, which may be used to steal your users cookies or simply annoy them.

Solution : Disable this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ocean12 guestbook";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
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


dirs = make_list(cgi_dirs(), "/guestbook");

foreach d (dirs)
{
 req = http_get(item:string(d, "/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 
 if ( res == NULL ) exit(0);
 if("Ocean<i>12</i>" >< res)
 {
  vers = strstr(res, "ASP Guestbook Manager</a> v1.00");
  if(vers)security_warning(port);
  exit(0);
 }
}

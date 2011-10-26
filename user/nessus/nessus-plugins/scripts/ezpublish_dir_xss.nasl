#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Ferruh Mavituna" <ferruh@mavituna.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: EzPublish Directory XSS Vulnerability
#  Date: Fri, 16 May 2003 06:22:20 +0300
#

if (description)
{
 script_id(11644);
 script_bugtraq_id(7616);
 script_version ("$Revision: 1.11 $");

 script_name(english:"ezPublish Directory Cross Site Scripting");
 desc["english"] = "
The remote host is using ezPublish, a content management system.

There is a flaw in the remote ezPublish which lets an attacker
perform a cross site scripting attack.  An attacker may use this
flaw to steal the cookies of your legitimate users.


Solution : Upgrade to ezPublish 3
Risk factor : Low / Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if ezPublish is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, '/index.php/article/articleview/<img%src="javascript:alert(document.cookie)">');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "javascript:alert(document.cookie)" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}


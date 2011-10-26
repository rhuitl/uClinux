#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18265);
 script_bugtraq_id(13632);
 script_version ("$Revision: 1.2 $");

 name["english"] = "Skull-Splitter Guestbook Multiple HTML Injection Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the Skull-Splitter guestbook, a guestbook
written in PHP.
The remote version of this software is vulnerable to cross-site
scripting attacks. Inserting special characters into the subject
or message content can cause arbitrary code execution for third
party users, thus resulting in a loss of integrity of their 
system.

Solution : None at this time
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Skull-Splitter Guestbook Multiple HTML Injection Vulnerabilities";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

function check(url)
{
 req = http_get(item:url +"/guestbook.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( egrep(pattern:"Powered by.*Skull-Splitter's PHP Guestbook ([0-1]\..*|2\.[0-2][^0-9])", string:res) )
 {
     security_warning(port);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs(), "/guestbook") )
{
  check(url:dir);
}

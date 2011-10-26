#
# Script Written By Ferdy Riphagen (GPL)
# <f.riphagen@nsec.nl>
#

if (description) {
script_id(19947);
script_version("$Revision: 1.5 $");

script_cve_id("CVE-2005-3063");
script_bugtraq_id(14933);

name["english"] = "MailGust SQL Injection Vulnerability";
script_name(english:name["english"]);

desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host appears to be running MailGust, a mailing list
manager, newsletter distribution tool and message board. 

A vulnerability was identified in MailGust, which may be exploited by
remote attackers to execute arbitrary SQL commands. 

See also :

http://retrogod.altervista.org/maildisgust.html

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
script_description(english:desc["english"]);

summary["english"] = "Check if MailGust is vulnerable to SQL Injection.";
script_summary(english:summary["english"]);

script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/mailgust", "/forum", "/maillist", "/gust", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 # Make sure the affected script exists.
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (res == NULL) exit(0);

 if (egrep(pattern:">Powered by <a href=[^>]+>Mailgust", string:res)) {
  req = string(
  "POST ",dir,"/index.php HTTP/1.0\r\n",
  "Content-Length: 64\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
  "method=remind_password&list=maillistuser&email='&showAvatar=\r\n\r\n");

  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);
  debug_print(recv);

  if(egrep(pattern: "SELECT.*FROM.*WHERE", string:recv))
  {
   security_note(port);
   exit(0);
  }
 }
}

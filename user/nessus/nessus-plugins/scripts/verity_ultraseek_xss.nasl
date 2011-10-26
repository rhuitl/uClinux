#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Michael Krax
# This script is released under the GNU GPL v2
#

if(description)
{
  script_id(17226);
  script_bugtraq_id(12617);
  script_cve_id("CVE-2005-0514");
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"14045");
   
  script_version("$Revision: 1.4 $");
  script_name(english:"Verity Ultraseek search request XSS");

 desc["english"] = "
The remote host runs Verity Ultraseek, an Enterprise Search Engine Software.

This version is vulnerable to cross-site scripting and remote script 
injection due to a lack of sanitization of user-supplied data.
Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

Solution: Upgrade to version 5.3.3 or higher
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks  Verity Ultraseek search request XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 8765);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8765);
if (!port) exit(0);
 
if ( ! get_port_state(port))exit(0);

function check(loc)
{
  buf = http_get(item:string(loc,"/help/copyright.html"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  if( r == NULL )exit(0);
  
  #<h3>Verity Ultraseek 5.3.1</h3>
  if(("<title>About Verity Ultraseek</title>" >< r) && 
   egrep(pattern:"Verify Ultraseek 5\.([23]\.[12]|3[^0-9])", string:r))
  {
    security_warning(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

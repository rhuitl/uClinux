#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Positive Technologies - www.maxpatrol.com
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15541);
  script_cve_id("CVE-2004-2207", "CVE-2004-2208", "CVE-2004-2209");
  script_bugtraq_id(11424);
  if (defined_func("script_xref")) 
  {
    script_xref(name:"OSVDB", value:"10760");
    script_xref(name:"OSVDB", value:"10761");
    script_xref(name:"OSVDB", value:"10762");
  }
  script_version("$Revision: 1.4 $");
  script_name(english:"IdealBB multiple flaws");
 
 desc["english"] = "
The remote host is running IdealBB, a web based bulletin board 
written in ASP.

The remote version of this software is vulnerable to multiple 
flaws: SQL injection, cross-site scripting and HTTP response splitting 
vulnerabilities. 

Solution: Upgrade to the latest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);

  script_summary(english:"Checks IdealBB version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  buf = http_get(item:string(req,"/idealbb/default.asp"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<title>The Ideal Bulletin Board</title>.*Ideal BB Version: 0\.1\.([0-4][^0-9]|5[^.]|5\.[1-3][^0-9])", string:r))
  {
 	http_close_socket(soc);
 	security_hole(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
if(!can_host_asp(port:port))exit(0);

soc = http_open_socket(port);
if(soc)
{
  foreach dir (cgi_dirs())
  {
    check(req:dir);
  }
  http_close_socket(soc);
}
exit(0);

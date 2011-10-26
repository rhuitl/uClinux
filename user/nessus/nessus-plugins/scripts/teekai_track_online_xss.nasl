#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: frog frog <leseulfrog@hotmail.com>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15707);
  script_cve_id("CVE-2002-2055");
  script_bugtraq_id(4924);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:4163);
  
  script_version("$Revision: 1.4 $");
  script_name(english:"TeeKai Tracking Online XSS");

 
 desc["english"] = "
The remote host runs Teekai Tracking Online, a PHP script used 
for tracking the number of user's on a Web site. 
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks XSS in TeeKai Tracking Online");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss" ) ) exit(0);

if(get_port_state(port))
{
 buf = http_get(item:"/page.php?action=view&id=1<script>foo</script>", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
}

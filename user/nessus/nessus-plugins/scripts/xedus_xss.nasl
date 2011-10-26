#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: James Bercegay of the GulfTech Security Research Team
# This script is released under the GNU GPLv2

if(description)
{
  script_id(14647);
  script_cve_id("CVE-2004-1645");
  script_bugtraq_id(11071);
  script_version("$Revision: 1.11 $");
  script_name(english:"Xedus XSS");

 
 desc["english"] = "
The remote host runs Xedus Peer to Peer webserver.
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution: Upgrade to the latest version and 
remove .x files located in ./sampledocs folder
	
Risk factor : Medium";
  script_description(english:desc["english"]);

  script_summary(english:"Checks XSS in Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("xedus_detect.nasl", "cross_site_scripting.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/test.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	exit(0);
  }
  buf = http_get(item:"/TestServer.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	exit(0);
  }
  buf = http_get(item:"/testgetrequest.x?param=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	exit(0);
  }
  http_close_socket(soc);
 }
}
exit(0);

#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref:  Michal Blaszczak <wacky nicponie org>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14685);
 script_cve_id("CVE-2004-1665");
 script_bugtraq_id(11124);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "PsNews XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running a version of PsNews (a content management system)
which is older than 1.2.

This version is affected by multiple cross-site scripting flaws. An attacker
may exploit these to steal the cookies from legitimate users of this website.

Solution : Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "check PsNews XSS flaws";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
		
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port) exit(0);

if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  foreach dir ( cgi_dirs() )
  {
  buf = http_get(item:dir + "/index.php?function=show_all&no=%253cscript>foo%253c/script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
  buf = http_get(item:dir + "/index.php?function=add_kom&no=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
 }
}

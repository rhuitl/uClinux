#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Dr_insane
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(14681);
  script_bugtraq_id(11111);
  if ( defined_func("script_xref") ) 
  {
    script_xref(name:"OSVDB", value:9514);
    script_xref(name:"OSVDB", value:9515);
    script_xref(name:"OSVDB", value:9516);
  }
  script_version("$Revision: 1.4 $");
  
  script_name(english:"Keene digital media server XSS");

 
 desc["english"] = "
The remote host runs Keene digital media server, a webserver
used to share digital information.


This version is vulnerable to multiple cross-site scripting attacks which
may allow an attacker to steal the cookies of users of this site.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks XSS in Keene server");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/dms/slideshow.kspx?source=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
buf = http_get(item:"/dms/dlasx.kspx?shidx=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
buf = http_get(item:"/igen/?pg=dlasx.kspx&shidx=<script>foo</script>", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
buf = http_get(item:"/dms/mediashowplay.kspx?pic=<script>foo</script>&idx=0", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
buf = http_get(item:"/dms/mediashowplay.kspx?pic=0&idx=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }

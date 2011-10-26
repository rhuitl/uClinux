#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on Noam Rathaus script
#
#  Ref: Ben Drysdale <ben@150bpm.co.uk>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
  script_id(15480);
  script_bugtraq_id(9497);
  script_version("$Revision: 1.4 $");
  name["english"] = "Xoops viewtopic.php Cross Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-
site scripting attacks. 

Description :

The weblinks module of XOOPS contains a file named 'viewtopic.php' in
the '/modules/newbb' directory.  The code of the module insufficently
filters out user provided data.  The URL parameter used by
'viewtopic.php' can be used to insert malicious HTML and/or JavaScript
in to the web page. 

See also :

http://www.securitytracker.com/alerts/2004/Jan/1008849.html
 
Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Xoops viewtopic.php XSS";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:path + '/modules/newbb/viewtopic.php?topic_id=14577&forum=2\"><script>foo</script>', port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"<script>foo</script>", string:res))
 {
  security_note(port);
  exit(0);
 }
}

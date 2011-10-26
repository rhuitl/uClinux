#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  ref : Oliver Karow <oliver.karow@gmx.de>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18213);
 script_cve_id("CVE-2005-1118");
 script_bugtraq_id(13168);
 script_version("$Revision: 1.3 $");
 
 script_name(english:"RSA Security RSA Authentication Agent For Web XSS");
 desc["english"] = "
The remote host seems to be running the RSA Security RSA Authentication 
Agent for web.

The remote version of this software is contains an input validation
flaw in the 'postdata' variable. An attacker may use it to perform a 
cross site scripting attack.

Solution: Upgraded to version 5.3 or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Test for XSS flaw in RSA Security RSA Authentication Agent For Web");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:'/WebID/IISWebAgentIF.dll?postdata="><script>foo</script>', port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);
if ("<TITLE>RSA SecurID " >< res && ereg(pattern:"<script>foo</script>", string:res) )
       security_warning(port);

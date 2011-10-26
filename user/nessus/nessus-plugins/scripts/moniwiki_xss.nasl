#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: SSR Team
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15566);
 script_version("$Revision: 1.7 $");
 
 script_cve_id("CVE-2004-1632");
 script_bugtraq_id(11516);
 script_xref(name:"OSVDB", value:"11124");

 script_name(english:"MoniWiki XSS");
 desc["english"] = "
The remote host seems to be running MoniWiki, a wiki web application 
written in PHP.

The remote version of this software is vulnerable to cross-site scripting 
attacks, through the script 'wiki.php'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution in users' browsers resulting in a loss of integrity.

Solution: Upgrade to version 1.0.9 of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Test for XSS flaw in MoniWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_dependencie("http_version.nasl");
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/wiki.php/<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<wikiHeader>" >< res && "<script>foo</script>" >< res )
 {
 	security_warning(port);
	exit(0);
 }
}

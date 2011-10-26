#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Megasky <magasky@hotmail.com>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18259);
script_cve_id("CVE-2005-1612", "CVE-2005-1613");
 script_bugtraq_id(13624, 13625);
 script_version("$Revision: 1.4 $");
 
 script_name(english:"OpenBB XSS and SQL injection flaws");
 desc["english"] = "
The remote host seems to be running OpenBB, a forum management system written
in PHP.

The remote version of this software is vulnerable to cross-site scripting 
attacks, and SQL injection flaws.

Using a specially crafted URL, an attacker may execute arbitrary commands against
the remote SQL database or use the remote server to set up a cross site scripting
attack.

Solution: Upgrade to version 1.0.9 of this software or newer
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Detects openBB version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
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

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if (ereg(pattern:'Powered by <a href="http://www.openbb.com/" target="_blank">Open Bulletin Board</a>[^0-9]*1\\.(0[^0-9]|0\\.[0-8][^0-9])<br>', string:res))
 {
 	security_hole(port);
	exit(0);
 }
}

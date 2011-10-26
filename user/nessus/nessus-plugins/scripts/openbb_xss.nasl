#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: gr00vy <groovy2600@yahoo.com.ar>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(14822);
 script_bugtraq_id(9303);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"3220");
 script_version("$Revision: 1.5 $");
 
 script_name(english:"OpenBB XSS");
 desc["english"] = "
The remote host seems to be running OpenBB, a forum management system written
in PHP.

The remote version of this software is vulnerable to cross-site scripting 
attacks, through the script 'board.php'.

Using a specially crafted URL, an attacker can cause arbitrary code execution 
for third party users, thus resulting in a loss of integrity of their system.

Solution: Upgrade to the latest version of this software.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Tests for XSS flaw in openBB board.php");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_dependencie("cross_site_scripting.nasl");
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


if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


foreach d (make_list( "/openbb", cgi_dirs()))
{
 req = http_get(item:string(d, "/board.php?FID=%3Cscript%3Efoo%3C/script%3E"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"<script>foo</script>", string:res))
 {
 	security_warning(port);
	exit(0);
 }
}

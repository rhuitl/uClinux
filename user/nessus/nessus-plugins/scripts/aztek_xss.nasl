#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: benji lemien <benjilenoob@hotmail.com>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15785);
 script_bugtraq_id( 11654 );
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"11704");
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Aztek Forum XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remoet web server contains a PHP script which is vulnerable to a cross
site scripting issue

Description : 

The remote host is using Aztek Forum, a web forum written in PHP.

A vulnerability exists the remote version of this software - more
specifically in the script 'forum_2.php', which may allow an attacker to 
set up a cross site scripting attack using the remote host.

Solution : 

Upgrade to the latest version of this software

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks XSS in Aztek Forum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 req = http_get(item:string(path, "/forum_2.php?msg=10&return=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if ( "forum_2.php?page=<script>foo</script>" >< res )
 {
  security_note(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 

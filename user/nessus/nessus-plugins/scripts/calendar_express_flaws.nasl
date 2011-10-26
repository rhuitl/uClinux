#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: aLMaSTeR HacKeR
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(19749);
 script_bugtraq_id(14504, 14505);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Calendar Express Multiple Flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script which is vulnerable to a cross
site scripting and SQL injection vulnerability.

Description :

The remote host is using Calendar Express, a PHP web calendar.

A vulnerability exists in this version which may allow an attacker to 
execute arbitrary HTML and script code in the context of the user's browser, 
and SQL injection.

An attacker may exploit these flaws to use the remote host to perform attacks
against third-party users, or to execute arbitrary SQL statements on the remote
SQL database.

Solution : 

Upgrade to the latest version of this software.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Calendar Express XSS and SQL flaws";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
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
include("global_settings.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") )
 {
   	security_warning(port);
   exit(0);
 }
}

if (thorough_tests) dirs = make_list("/calendarexpress", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}

# base on cross_site_scripting.nasl, from various people
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

if (description)
{
 script_id(11010);
 script_bugtraq_id(2401);
 script_version("$Revision: 1.12 $");
 script_name(english:"WebSphere Cross Site Scripting");
 desc["english"] = "
Synopsis :

The remote web server is itself prone to cross-site scripting attacks. 

Description :

The remote web server seems to be vulnerable to cross-site scripting
vulnerabilities because it fails to sanitize input supplied as a
filename when displaying an error page. 

The vulnerability would allow an attacker to make the server present the
user with the attacker's JavaScript/HTML code.  Since the content is
presented by the server, the user will give it the trust level of the
server (for example, the trust level of banks, shopping centers, etc. 
would usually be high). 

Solution : 

Upgrade to the latest version of WebSphere.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote host is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"(c) 2002 Renaud Deraison");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
req = http_get(item:string("/../", xss), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( res == NULL ) exit(0);
if(xss >< res) security_note(port);

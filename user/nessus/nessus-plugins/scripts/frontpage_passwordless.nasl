#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11455);
 script_version ("$Revision: 1.7 $");

 name["english"] = "Passwordless frontpage installation";
 script_name(english:name["english"]);

 desc["english"] = "
The remote FrontPage server seems to not be password protected.

As a result, an attacker may 'deface' the remote web server simply
by using Microsoft Frontpage

Solution : Set a password
See also : http://www.ciac.org/ciac/bulletins/k-048.shtml
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote web server is password protected";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


dirs = get_kb_list(string("www/", port, "/content/directories"));
if(!isnull(dirs))dirs = make_list("", dirs);
else dirs = make_list("");

unpassworded = NULL;

foreach dir (dirs)
{ 
 res = http_keepalive_send_recv(port:port, data:http_get(item:string(dir, "/_vti_inf.html"), port:port));
 if (res == NULL ) exit(0);
 if("FPAuthorScriptUrl" ><  res)
 {
 str = egrep(pattern:"FPAuthorScriptUrl", string:res);
 auth = ereg_replace(pattern:'.*FPAuthorScriptUrl="([^"]*)".*', string:str, replace:"\1");
 content = "method=open+service%3a5%2e0%2e2%2e2623&service%5fname=" + str_replace(string:dir, find:"/", replace:"%2f");
 
 req = string("POST ", dir, "/", auth, " HTTP/1.1\r\n",
"MIME-Version: 1.0\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: MSFrontPage/5.0\r\n",
"Accept: auth/sicily\r\n",
"Content-Length: ", strlen(content), "\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"X-Vermeer-Content-Type: application/x-www-form-urlencoded\r\n\r\n",
content);

 res = http_keepalive_send_recv(port:port, data:req);
 if(egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) && "x-vermeer-rpc" >< res) { if ( dir == "") dir = "/"; unpassworded += dir + '\n'; }
 }
}

if(unpassworded != NULL)
{
 report = "
The following directories have frontpage enabled, but are not password protected :

" + unpassworded + "

Anyone can use Microsoft FrontPage to modify them.

Solution : Set a password on the frontpage installation of these directories
See also : http://www.ciac.org/ciac/bulletins/k-048.shtml
Risk factor : High";

 security_hole(port:port, data:report);
}

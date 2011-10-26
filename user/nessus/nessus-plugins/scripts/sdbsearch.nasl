
#
# This script is released under the GPL
#
#
if(description)
{
 script_id(10720); 
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-1130");
 
 name["english"] = "sdbsearch.cgi";

 script_name(english:name["english"]);
 
 desc["english"] = "
The SuSE cgi 'sdbsearch.cgi' is installed.
This cgi allows a local (and possibly remote) user
to execute arbitrary commands with the privileges of
the HTTP server.

Solution : modify the script so that it filters
the HTTP_REFERRER variable, or delete it.

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of the sdbsearch.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script was written by Renaud Deraison");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


req = string("GET /sdbsearch.cgi?stichwort=anything HTTP/1.1\r\n",
"Referer: http://", get_host_name(), "/../../../../etc\r\n",
"Host: ", get_host_name(), "\r\n\r\n");

r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL )exit(0);
if("htdocs//../../../../etc/keylist.txt" >< r)security_hole(port);

foreach dir (cgi_dirs())
{
req = string("GET ", dir, "/sdbsearch.cgi?stichwort=anything HTTP/1.1\r\n",
"Referer: http://", get_host_name(), "/../../../../etc\r\n",
"Host: ", get_host_name(), "\r\n\r\n");
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL )exit(0);
if("htdocs//../../../../etc/keylist.txt" >< r)security_hole(port);
}

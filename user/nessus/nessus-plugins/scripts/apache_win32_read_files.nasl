#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# 
#

if(description)
{
 script_id(11210);
 script_bugtraq_id(6660);
 script_cve_id("CVE-2003-0017");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0003"); 
 script_version("$Revision: 1.7 $");
 
 name["english"] = "Apache < 2.0.44 file reading on Win32";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache for Windows which is older than 2.0.44

There is a flaw in this version which allow
an attacker to read files they should not have access
to, by appending special chars to them.

Solution : Upgrade to version 2.0.44
See also : http://www.apache.org/dist/httpd/Announcement.html
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Requests /< and gets the output";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port: port);
 if(!banner)exit(0);
 if("Server: Apache" >< banner && "Win32" >< banner )
 {
  req = http_get(item:"/<<<<<<<<<<<<", port:port);
  soc = http_open_socket(port);
  if(!soc)exit(0);
  
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  http_close_socket(soc);
  # Apache 2.0.44 replies with a code 403
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 301 ", string:r))security_hole(port);
 }
}

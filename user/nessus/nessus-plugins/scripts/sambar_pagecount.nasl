#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(10711);
 script_bugtraq_id(3091, 3092);
 script_cve_id("CVE-2001-1010");
 script_version ("$Revision: 1.15 $");
 name["english"] = "Sambar webserver pagecount hole";
 name["francais"] = "Sambar webserver pagecount hole";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
By default, there is a pagecount script with Sambar Web Server
located at http://sambarserver/session/pagecount
This counter writes its temporary files in c:\sambardirectory\tmp.
It allows to overwrite any files on the filesystem since the 'page'
parameter is not checked against '../../' attacks.

Reference : http://www.securityfocus.com/archive/1/199410
Risk factor : High
Solution : Remove this script";

 script_description(english:desc["english"]);
 
 summary["english"] = "Make a request like http://www.example.com/session/pagecount";
 summary["francais"] = "Fait une requête du type http://www.example.com/session/pagecount";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Vincent Renardias",
		francais:"Ce script est Copyright (C) 2001 Vincent Renardias");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:"/session/pagecount", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  if( ("Server: SAMBAR" >< data) && !ereg(string:data, pattern:"^404"))
  {
   security_hole(port);
  }
 }
}

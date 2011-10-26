#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10249);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0531");
 
 name["english"] = "EXPN and VRFY commands";
 name["francais"] = "Commandes EXPN et VRFY";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server answers to the EXPN and/or VRFY commands.

The EXPN command can be used to find the delivery address of mail aliases, or 
even the full name of the recipients, and the VRFY command may be used to check the validity of an account.


Your mailer should not allow remote users to use any of these commands, 
because it gives them too much information.


Solution : if you are using Sendmail, add the option :

	O PrivacyOptions=goaway

       in /etc/sendmail.cf.

Risk factor : Low"; 
	

 desc["francais"] = "Le serveur SMTP distant
répond aux requètes EXPN et/ou VRFY.

La commande EXPN peut être utilisée pour 
trouver l'adresse de livraison des
aliases mail, et même parfois le
vrai nom du propriétaire d'un login.
La commande VRFY quant à elle,
peut etre utilisée pour vérifier
l'existence d'un accompte.

Votre mailer ne devrait pas
laisser les utilisateurs 
faire ces commandes, car
elles leur donne trop d'informations.

Solution : si vous utilisez sendmail,
ajoutez l'option :

	O PrivacyOptions=goaway
	
dans /etc/sendmail.cf.

Facteur de risque : Faible";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "EXPN and VRFY checks"; 
 summary["francais"] = "Vérification de EXPN et VRFY";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_exclude_keys("SMTP/wrapped");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = 25;
if(!get_port_state(port))exit(0);

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  b = smtp_recv_banner(socket:soc);
  if ( ! b ) exit(0);
  s = string("HELO example.com\r\n");
  send(socket:soc, data:s);
  r = smtp_recv_line(socket:soc);

  s = string("EXPN root\r\n");
  send(socket:soc, data:s);
  r = smtp_recv_line(socket:soc);
  
  
  if(ereg(string:r, pattern:"^(250|550)(-| ).*$"))
  {
# exim hack
    if(!ereg(string:r, pattern:"^550 EXPN not available.*$") &&
       !ereg(string:r, pattern:"^550.*Administrative prohibition.*$") &&
       !ereg(string:r, pattern:"^550.*Access denied.*$"))
    {
      security_warning(port);
      set_kb_item(name:"SMTP/expn",value:TRUE);
    } 
  } 
  else {
	s = string("VRFY root\r\n");
	send(socket:soc, data:s);
	r = smtp_recv_line(socket:soc);
	if(ereg(string:r, pattern:"^(250|550)(-| ).*$"))
	       {
	        send(socket:soc, data:string("VRFY random", rand(), "\r\n"));
		r = smtp_recv_line(socket:soc);
		if(ereg(string:r, pattern:"^(250|550)(-| ).*$"))exit(0);
		security_warning(port);
		set_kb_item(name:"SMTP/vrfy",value:TRUE);
		}
       }
   close(soc);
}

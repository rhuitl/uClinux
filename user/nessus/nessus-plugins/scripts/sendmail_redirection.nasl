#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10250);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "Sendmail redirection check";
 name["francais"] = "Vérification de la redirection de sendmail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server is vulnerable to a redirection attack. That is, if a 
mail is sent to :

		user@hostname1@victim
		
Then the remote SMTP server (victim) will happily send the mail to :
		user@hostname1
		
Using this flaw, an attacker may route a message through your firewall, in 
order to exploit other SMTP servers that can not be reached from the
outside.

Solution : In sendmail.cf, at the top of ruleset 98, in /etc/sendmail.cf, 
insert the following statement :
R$*@$*@$*       $#error $@ 5.7.1 $: '551 Sorry, no redirections.'

Risk factor : Low"; 
	

 desc["francais"] = "
Le serveur SMTP distant est vulnérable à une attaque
de redirection. C'est à dire que si un mail est 
envoyé à :

	user@hostname1@victim
	
Alors le serveur SMTP distant (victim) va joyeusement
renvoyer un mail à :

	user@hostname1
	
En utilisant ce problème, un pirate peut router un
message au travers de votre firewall, afin d'exploiter
d'autres serveurs SMTP peut etre moins sécurisés 
qui seraient normallement inaccessibles de l'exterieur.

*** CETTE ALERTE EST PEUT ETRE FAUSSE, PUISQUE CERTAINS
    SERVEURS SMTP TELS QUE POSTFIX NE SE PLAINDRONT
    PAS MAIS IGNORERONT CE MESSAGE SILENCIEUSEMENT ***
    
Solution : si vous utilisez sendmail, alors dans /etc/sendmail.cf,
en haut du ruleset 98, insérez :

R$*@$*@$*       $#error $@ 5.7.1 $: '551 Sorry, no redirections.'

Facteur de risque : Faible";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Redirection check"; 
 summary["francais"] = "Vérification de redirection";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl", "smtpserver_detect.nasl");
 script_exclude_keys("SMTP/postfix", "SMTP/qmail");
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
  if(!b) exit(0);
  if ( "Sendmail" >!< b )exit(0);

  domain = ereg_replace(pattern:"[^\.]*\.(.*)",
 		       string:get_host_name(),
		       replace:"\1");		
  s = string("HELO ", domain, "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  s = string("MAIL FROM: root@", get_host_name(), "\r\n"); 
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  s = string("RCPT TO: root@host1@", get_host_name(), "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:255);
  if(ereg(pattern:"^250 .*", string:r))security_warning(port);
  close(soc);
}

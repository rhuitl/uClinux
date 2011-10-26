#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10284);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-1516");
 
 name["english"] = "TFS SMTP 3.2 MAIL FROM overflow";
 name["francais"] = "Dépassement de buffer dans TFS SMTP 3.2 suite à la commande MAIL FROM";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There seem to be a buffer overflow in the remote SMTP server
when the server is issued a too long argument to the 'MAIL FROM'
command.

This problem may allow an attacker to prevent this host
to act as a mail host and may even allow him to execute
arbitrary code on this system.


Solution : If you are using TFS SMTP, upgrade to version 4.0.
If you do not, then inform your vendor of this vulnerability
and wait for a patch.

Risk factor : High";


 desc["francais"] = "
Il semble y avoir un dépassement de buffer dans le
serveur SMTP distant lorsque celui-ci reçoit un
argument trop long a la commande 'MAIL FROM'.

Ce problème peut permettre à un pirate d'empecher
cette machine d'agir comme un serveur de mail, et
peut meme lui permettre d'executer du code arbitraire
sur ce système.


Solution : Si vous utilisez TFS SMTP, alors mettez-le à jour
en version 4.0. Si ce n'est pas le cas, informez votre 
vendeur de cette vulnérabilité et attendez un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Overflows a buffer in the remote mail server"; 
 summary["francais"] = "Dépassemement de buffer dans le serveur de mail distant";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped",
 		     "SMTP/postfix",
		     "SMTP/qmail");
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

if(safe_checks())
{ 
 banner = get_smtp_banner(port:port);
 
 if(banner)
 {
  if(egrep(string:banner,
  	  pattern:"TFS SMTP Server [1-3]\..*"))
	  {
	  alrt = "
The remote TFS SMTP server is vulnerable to a buffer
overflow when issued a too long argument to the 
'MAIL FROM' command.

An attacker can use this flaw to execute arbitrary
code on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to version 4.0
Risk factor : High";
   	  security_hole(port:port, data:alrt);
	  }
 }
 
 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);	
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: ", crap(1024), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 if(!buf){
  close(soc);
  soc = open_sock_tcp(port);
  if ( soc ) s  = smtp_recv_banner(socket:soc);
  else s = NULL;
  
  if(!s){
	 security_hole(port);
	 set_kb_item(name:string("SMTP/", port, "/mail_from_overflow"), value:TRUE);
	}
			
  }
 }
 close(soc);
 }
}

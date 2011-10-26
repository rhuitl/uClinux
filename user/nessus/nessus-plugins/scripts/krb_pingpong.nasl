
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10640);
 script_cve_id("CVE-1999-0103");
 script_version ("$Revision: 1.10 $");
 name["english"] = "Kerberos PingPong attack";
 name["francais"] = "Kerberos PingPong attack";
 script_name(english:name["english"], francais:name["francais"]);

    desc["english"] = "
The remote host is running a kerberos server, which seems to be vulnerable 
to a 'ping-pong' attack.

When contacted on the UDP port, this service always respond, even
to malformed requests.

An easy attack is 'ping-pong' in which an attacker spoofs a packet between 
two machines running this service. This will cause them to spew characters at 
each other, slowing the machines down and saturating the network. 
					 
Solution : Disable this service if you do not use it.
Risk factor : Low";

 

 script_description(english:desc["english"]);
 

 summary["english"] = "Checks for the presence of a bad krb server";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");

 family["english"] = "Misc.";
 script_family(english:family["english"]);
 exit(0);
}
 

if(!get_udp_port_state(464))exit(0);

soc = open_sock_udp(464);
crp = crap(25);
if(soc)
{
 send(socket:soc, data:crp);
 r = recv(socket:soc, length:255);
 if(r){
	send(socket:soc, data:r);
	r = recv(socket:soc, length:255);
	if ( r ) security_warning(port:464, protocol:"udp");
     }
}

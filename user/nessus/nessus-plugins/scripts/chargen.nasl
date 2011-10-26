#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#
#T


if(description)
{
 script_id(10043);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0103"); 
 name["english"] = "Chargen";
 name["francais"] = "Chargen";
 script_name(english:name["english"], francais:name["francais"]);

    desc["english"] = "
Synopsis :

The remote host is running a 'chargen' service.

Description :

When contacted, chargen responds with some random characters (something
like all the characters in the alphabet in a row). When contacted via UDP, it 
will respond with a single UDP packet. When contacted via TCP, it will 
continue spewing characters until the client closes the connection. 

The purpose of this service was to mostly to test the TCP/IP protocol
by itself, to make sure that all the packets were arriving at their
destination unaltered. It is unused these days, so it is suggested
you disable it, as an attacker may use it to set up an attack against
this host, or against a third party host using this host as a relay.

An easy attack is 'ping-pong' in which an attacker spoofs a packet between 
two machines running chargen. This will cause them to spew characters at 
each other, slowing the machines down and saturating the network.
					 
Solution : 

- Under Unix systems, comment out the 'chargen' line in /etc/inetd.conf 
  and restart the inetd process

- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen
  
 Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


 script_description(english:desc["english"]);
 

 summary["english"] = "Checks for the presence of chargen";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");

 exit(0);
}
 
#
# The script code starts here
#

include("misc_func.inc");
include("pingpong.inc");



if(get_port_state(19))
{
 p = known_service(port:19);
 if(!p || p == "chargen")
 {
 soc = open_sock_tcp(19);
 if(soc)
  {
    a = recv(socket:soc, length:255, min:255);
    if(strlen(a) > 255)security_note(19);
    close(soc);
  }
 }
}

		
if(get_udp_port_state(19))
{		  
 udpsoc = open_sock_udp(19);
 data = string("\r\n");
 send(socket:udpsoc, data:data);
 b = recv(socket:udpsoc, length:1024);
 if(strlen(b) > 255)security_note(port:19,protocol:"udp");
 
 close(udpsoc);
}


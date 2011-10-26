#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10198);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0103");
 name["english"] = "Quote of the day";
 name["francais"] = "Quote of the day";
 script_name(english:name["english"], francais:name["francais"]);

    desc["english"] = "
Synopsis :

The quote service (qotd) is running on this host.

Description :

A server listens for TCP connections on TCP port 17. Once a connection 
is established a short message is sent out the connection (and any 
data received is thrown away). The service closes the connection 
after sending the quote.

Another quote of the day service is defined as a datagram based
application on UDP.  A server listens for UDP datagrams on UDP port 17.
When a datagram is received, an answering datagram is sent containing 
a quote (the data in the received datagram is ignored).


An easy attack is 'pingpong' which IP spoofs a packet between two machines
running qotd. This will cause them to spew characters at each other,
slowing the machines down and saturating the network.

Solution : 
 
- Under Unix systems, comment out the 'qotd' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpQotd
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpQotd
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";

 
 script_description(english:desc["english"]);
 

 summary["english"] = "Checks for the presence of qotd";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "find_service2.nasl");

 exit(0);
}
 
#
# The script code starts here
#
include("misc_func.inc");

if(get_port_state(17))
{
 p = known_service(port:17);
 if(!p || p == "qotd")
 {
 soc = open_sock_tcp(17);
 if(soc)
  {
    a = recv_line(socket:soc, length:1024);
    if(a)security_note(17);
    close(soc);
  }
 }
}

if(get_udp_port_state(17))
{		  
 udpsoc = open_sock_udp(17);
 send(socket:udpsoc, data:'\r\n');
 b = recv(socket:udpsoc, length:1024);
 if(b)security_note(port:17, protocol:"udp");
 close(udpsoc);
}

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10052);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0103");
 name["english"] = "Daytime";
 name["francais"] = "Daytime";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

A daytime service is running on the remote host

Description :

The remote host is running a 'daytime' service. This service
is designed to give the local time of the day of this host
to whoever connects to this port.
 
The date format issued by this service may sometimes help an attacker 
to guess the operating system type of this host, or to set up 
timed authentication attacks against the remote host.

In addition to that, the UDP version of daytime is running, an attacker 
may link it to the echo port of a third party host using spoofing, thus 
creating a possible denial of service condition between this host and
a third party.

Solution :

- Under Unix systems, comment out the 'daytime' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDaytime
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpDaytime
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of daytime";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service2.nasl");

 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/daytime");
if (! port) port = 13;

if(get_port_state(port))
{
 k = 'FindService/tcp/'+port+'/spontaneous';
 a = get_kb_item(k);
 if (!a)
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   a = recv(socket:soc, length:1024);
   close(soc);
  }
  if (a) set_kb_item(name: k, value: a);
 }
 if(a) security_note(port);
}

include("pingpong.inc");

if(get_udp_port_state(13))
{
 udpsoc = open_sock_udp(13);
 data = '\n';
 send(socket:udpsoc, data:data);
 b = recv(socket:udpsoc, length:1024);
 
 if(b)security_note(port:13, protocol:"udp");
 
  # if (udp_ping_pong(port: 13, data: data, answer: b))
  #   security_hole(port:13, protocol:"udp");
  # else
     

 close(udpsoc);
}

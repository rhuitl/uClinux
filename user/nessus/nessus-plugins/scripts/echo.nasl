#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10061);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0103", "CVE-1999-0635");
 name["english"] = "Echo port open";
 name["francais"] = "Port echo ouvert";
 name["deutsch"] = "Echo Port offen";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "
Synopsis :

An echo service is running on the remote host.

Description :

The remote host is running the 'echo' service. This service 
echoes any data which is sent to it. 
 
This service is unused these days, so it is strongly advised that
you disable it, as it may be used by attackers to set up denial of
services attacks against this host.

Solution :

- Under Unix systems, comment out the 'echo' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpEcho
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpEcho
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the 'echo' port is open";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
		
 family["english"] = "Useless services";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 
 exit(0);
}


include("misc_func.inc");


pattern = string("Harmless Nessus echo test");

#
# The script code starts here
#
include("pingpong.inc");

port = get_kb_item("Services/echo");
if(!port)port = 7;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res = recv_line(socket:soc, length:1024);
  if(data == res)
   {
   security_note(port);
   register_service(port:port, proto:"echo");
   }
  close(soc);
  }
}

if(get_udp_port_state(port))
{
 soc = open_sock_udp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res2 = recv(socket:soc, length:1024);
  if(res2)
  {
  if(data ==  res2)security_note(port, protocol:"udp");
  #  if (udp_ping_pong(port: port, data: data, answer: res2))
      
  }
  close(soc);
 }
}


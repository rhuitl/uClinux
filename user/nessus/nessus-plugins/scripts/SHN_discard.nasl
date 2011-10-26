#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(11367);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-1999-0636");
 name["english"] = "Discard port open";
 name["francais"] = "Port 'discard' ouvert";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running a 'discard' service. This service
typically sets up a listening socket and will ignore all the
data which it receives. 

This service is unused these days, so it is advised that you
disable it.


Solution : 

- Under Unix systems, comment out the 'discard' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDiscard
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.

	
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the 'discard' port is open";
 summary["francais"] = "Vérifie si le port 'discard' est ouvert";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2003 StrongHoldNet",
		deutsch:"Dieses Skript ist Copyright geschützt. (C) 2003 StrongHoldNet");
		
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 family["deutsch"] = "Nutzlose Dienste";
 
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes");
 script_require_ports(9);
 
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = 9; # Discard is not supposed to run on any other port.
if(! service_is_unknown(port:port)) { exit(0); }

# We send between 17 and 210 bytes of random data.
# If the service is still listening without any output, we assume
# that 9/tcp is running 'discard'.
function check_discard(soc) {
  local_var i, n, res;
  if(!soc)
   return(0);

  n = send(socket:soc, data:string(crap(length:(rand()%193+17), data:string(rand())),"\r\n\r\n"));
  if (n<0)
   return(0);

  res = recv(socket:soc, length:1024, timeout:5);
  if(strlen(res) > 0)
   return(0);

  return(1);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(check_discard(soc:soc)) {
   security_note(port);
   register_service(port:port,proto:"discard");
   if(soc)
    close(soc);
 }
}

exit(0);

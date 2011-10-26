#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10021);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0629");
 name["english"] = "Identd enabled";
 name["francais"] = "Identd activé";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running an ident (also known as 'auth') daemon.

The 'ident' service provides sensitive information to potential 
attackers. It mainly says which accounts are running which services. 
This helps attackers to focus on valuable services (those
owned by root). If you do not use this service, disable it.

Solution : Under Unix systems, comment out the 'auth' or 'ident' 
line in  /etc/inetd.conf and restart inetd

Risk factor : Low";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if identd is installed";
 summary["francais"] = "Vérifie si identd est installé";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = get_kb_item("Services/auth");
if(!port)port = 113;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string("0,0\r\n");
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  seek = "ERROR";
  if(seek >< buf)
  {
   security_note(port);
   register_service(port:port, proto:"auth");
  }
  close(soc);
 }
}


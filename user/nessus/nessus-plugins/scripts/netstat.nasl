#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10157);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0650");
 name["english"] = "netstat";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a 'netstat' service on this port.

The 'netstat' service provides useful information to an attacker, since 
it gives away the state of the active connections. It is recommended that 
disable this service if you do not use it.

Risk factor : Low
Solution : comment out the 'netstat' line in /etc/inetd.conf and restart the
inetd process";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for netstat";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/netstat", 15);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
port = get_kb_item("Services/netstat");
if(!port)port = 15;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = recv_line(socket:soc, length:1024);
  data_low = tolower(data);
  if("active " >< data_low || "established" >< data_low || 
     "time_wait" >< data_low || "close_wait" >< data_low)
  {
    security_warning(port);
    register_service(port: port, proto: "Services/netstat");
  }
  close(soc);
 }
}

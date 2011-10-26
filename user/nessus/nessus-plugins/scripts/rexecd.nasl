#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10203);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0618");
 name["english"] = "rexecd";
 script_name(english:name["english"]);
 
 desc["english"] = "
The rexecd service is open. This service is design to 
allow users of a network to execute commands remotely.


However, rexecd does not provide any good means of authentication, so it 
may be abused by an attacker to scan a third party host.

Solution : comment out the 'exec' line in /etc/inetd.conf and restart the 
inetd process

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of rexecd";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rexecd", 512);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");


port = get_kb_item("Services/rexecd");
if(!port){
 p = known_service(port:512);
 if(p && p != "rexecd")exit(0);
 port = 512;
 }

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:string("0", raw_string(0), "root", raw_string(0), "FOOBAR!", raw_string(0), "id", raw_string(0)));
  r = recv_line(socket:soc, length:4096);
  if ( ! r ) exit(0);
  if(ord(r[0]) == 1)security_warning(port);
  close(soc);
 }
}

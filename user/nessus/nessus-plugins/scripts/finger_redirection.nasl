#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10073);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0105", "CVE-1999-0106");
 name["english"] = "Finger redirection check";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote finger service accepts to redirect requests. That is, users can 
perform requests like :

		finger user@host@victim

This allows an attacker to use this computer as a relay to gather information 
on a third party network.

Solution: Disable the remote finger daemon (comment out the 'finger' line
in /etc/inetd.conf and restart the inetd process) or upgrade it to a more
secure one.

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Finger user@host1@host2";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Finger abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  # cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  
  buf = string("root@", get_host_name(), "\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  data_low = tolower(data);
  
  if(data_low && !("such user" >< data_low) && 
     !("doesn't exist" >< data_low) && !("???" >< data_low)
     && !("welcome to" >< data_low) && !("forward" >< data_low)){
     		security_warning(port);
		set_kb_item(name:"finger/user@host1@host2", value:TRUE);
		}
  close(soc);
 }
}

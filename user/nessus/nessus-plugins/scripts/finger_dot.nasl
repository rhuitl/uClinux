#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10072);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0198");
 name["english"] = "Finger dot at host feature";
 script_name(english:name["english"]);
 
 desc["english"] = "

There is a bug in the remote finger service which, when triggered, allows
a user to force the remote finger daemon to  display the list of the accounts 
that have never been used, by issuing the request :

		finger .@target
		
This list will help an attacker to guess the operating system type. It will 
also tell him which accounts have never been used, which will often make him 
focus his attacks on these accounts.

Solution : disable the finger service in /etc/inetd.conf and restart the inetd
process, or upgrade your finger service.

Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Finger .@host feature";
 summary["francais"] = "Finger .@host feature";
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
  # Cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  
  buf = string(".\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(strlen(data)<100)exit(0);
  data_low = tolower(data);
  
  if(data_low && (!("such user" >< data_low)) && 
     (!("doesn't exist" >< data_low)) && (!("???" >< data_low))
     && (!("welcome to" >< data_low))){
     report = "
There is a bug in the remote finger service which, when triggered, allows
a user to force the remote finger daemon to  display the list of the accounts 
that have never been used, by issuing the request :

		finger .@target
		
This list will help an attacker to guess the operating system type. It will 
also tell him which accounts have never been used, which will often make him 
focus his attacks on these accounts.

Here is the list of accounts we could obtain : 
" + data + "

Solution : disable the finger service in /etc/inetd.conf and restart the inetd
process, or upgrade your finger service.

Risk factor : Medium";
     		security_warning(port:port, data:report);
		set_kb_item(name:"finger/.@host", value:TRUE);
		}

 }
}

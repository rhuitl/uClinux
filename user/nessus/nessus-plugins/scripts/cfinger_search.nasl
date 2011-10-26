#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10038);
 script_cve_id("CVE-1999-0259");
 
 script_version ("$Revision: 1.17 $");
 name["english"] = "Cfinger's search.**@host feature";
 name["francais"] = "Cfinger's search.**@host feature";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running 'cfingerd', a finger daemon. 
 
There is a bug in the remote cfinger daemon which allows 
anyone to get the lists of the users of this system, when
issuing the command :

	finger search.**@victim


This information can in turn be used by an attacker to set up
a brute force login attack against this host.

Solution : use another finger daemon or disable this service in /etc/inetd.conf
Risk factor : Low / Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "finger .@host feature";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Finger abuses";
 family["francais"] = "Abus de finger";
 script_family(english:family["english"], francais:family["francais"]);
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
  buf = string("search.**\r\n");

  send(socket:soc, data:buf);
  recv_line(socket:soc, length:2048);
  data = recv_line(socket:soc, length:2048);
  minus = "----";
  if(minus >< data)
  {
	for(i=1;i<11;i=i+1){
		data = recv_line(socket:soc, length:2048);
		if(!data)exit(0);
		}
	data = recv_line(socket:soc, length:2048);
	if(data){
  		data_low = tolower(data);
  		if(data_low && ("root" >< data_low)) 
		 {
     		 security_warning(port);
		 set_kb_item(name:"finger/search.**@host", value:TRUE);
		 }
		}
  }
  close(soc);
 }
}

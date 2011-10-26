#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10534);
 script_bugtraq_id(1803);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0915");

 name["english"] = "FreeBSD 4.1.1 Finger";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a bug in the remote finger service that allows anyone to read 
arbitrary files on this host by doing a 'finger' command on the name of 
targeted file. 

For instance :

	finger /etc/passwd@target
	

Will display the content of /etc/passwd

Solution : disable the finger service in /etc/inetd.conf and restart the inetd
process, or upgrade your finger daemon

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Finger /path/to/file";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
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
  buf = string("/etc/passwd\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(egrep(pattern:".*root:.*:0:[01]:", string:data))
  	security_hole(port);
 }
}

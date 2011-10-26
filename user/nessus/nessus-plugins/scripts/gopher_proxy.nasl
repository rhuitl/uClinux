#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16194);
 script_bugtraq_id(6782);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Gopherd Proxy Usage";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a Gopher server.

It is possible to make the remote server connect to third
party FTP sites by sending the request 'ftp://hostname.of.the.ftp.server'.

An attacker may exploit this flaw to connect to use the remote
gopher daemon as a proxy to connect to FTP servers without disclosing
their IP address.

An attacker could also exploit this flaw to 'ping' the hosts
of your network.


Solution : Disable FTP support in the remote gopher server
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if gopherd can be used as a proxy"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "Firewalls"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/gopher",70);
 exit(0);
}


port = get_kb_item("Services/gopher");
if ( ! port ) port = 70;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'ftp://ftp.nessus.org\r\n');
line = recv(socket:soc, length:4096, timeout:30);

if ( "You are user #" >< line ) security_hole(port);

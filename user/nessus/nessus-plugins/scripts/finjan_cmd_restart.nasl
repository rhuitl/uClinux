#
# (C) Tenable Network Security
#

if(description)
{ 
 script_id(12036);
 script_cve_id("CVE-2004-2107");
 script_bugtraq_id(9478);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Finjan restart command";
 script_name(english:name["english"]);
 
desc["english"] = "
The remote host is running a finjan proxy.

It is possible to use this proxy and force it to connect to itself,
to then issue administrative commands to this service.

An attacker may use this flaw to force this proxy to restart continuously,
although other administrative commands might be executable.

Solution : Block all connections to '*:ControlPort'
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "determines if the remote proxy can connect against itself";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Firewalls"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http_proxy", 3128);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;

if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 send(socket:soc, data:'CONNECT localhost:3141 HTTP/1.0\r\n\r\n');
 r = recv_line(socket:soc, length:4096); 
 if ( ! r ) exit(0);
 if ( "200 Connection established" >!< r ) exit(0);
 r = recv_line(socket:soc, length:4096); 
 if ( ! r ) exit(0);
 if ( 'Proxy-agent: Finjan' >< r ) security_warning(port);
 close(soc);
}

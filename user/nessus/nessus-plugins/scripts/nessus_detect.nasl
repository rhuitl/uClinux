#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

A Nessus daemon is listening on the remote port.

Description :

A Nessus daemon is listening on the remote port.  It is not
recommended to let anyone connect to this port.

Also, make sure that the remote Nessus installation has
been authorized.

Solution :

Filter incoming traffic to this port.

Risk factor : 

None";

if(description)
{
 script_id(10147);
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "Nessus Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to port 1241";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");
 script_require_ports(1241);
 script_dependencies("find_service2.nasl");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("global_settings.inc");

function nessus_detect(port)
{
 local_var soc, r;
 if ( ! get_port_state(port) ) exit(0);
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'< NTP/1.2 >\r\n');
 r = recv_line(socket:soc, length:4096);
 if ( '< NTP/1.2 >' >< r )
 {
   r = recv(socket:soc, length:7);
   close(soc);
   if ( "User : " >< r ) 
	{
	 register_service(proto:"nessus", port:port);
	 security_note(port);
	 exit(0);
	}
 }
 else close(soc);
}


if ( thorough_checks )
{
 port = get_unknown_svc();
 if( port && get_port_state(port)) nessus_detect(port:port);
}
else nessus_detect(port:1241);

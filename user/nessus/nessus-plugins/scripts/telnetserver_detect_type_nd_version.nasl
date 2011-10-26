#
# (C) Tenable Network Security
#
 desc["english"] = "
Synopsis :

A telnet server is listening on the remote port

Description :

The remote host is running a telnet server.
Using telnet is not recommended as logins, passwords and commands 
are transferred in clear text.

An attacker may eavesdrop on a telnet session and obtain the 
credentials of other users.

Solution : 

Disable this service and use SSH instead

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 desc_over_ssl = "
Synopsis :

A telnet server is listening on the remote port over SSL.

Description :

The remote host is running a telnet server on top of SSL.
Usually, telnet works over clear text, however the remote
implementation uses SSL, which makes it safe to use over
an untrusted network.

Solution : 

Disable this service if you do not use it.

Risk factor : 

None";

if(description)
{
 script_id(10281);
 script_version ("$Revision: 1.22 $");
 name["english"] = "Telnet Server Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Telnet Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");

 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 
 exit(0);
}


#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
  banner = get_telnet_banner(port: port);
  if(strlen(banner))
  {
   trp = get_port_transport(port);
   if ( trp <= ENCAPS_IP )
	{
	 report = desc["english"] + '\n\nPlugin output:\n\nRemote telnet banner:\n' + banner;
         security_warning(port:port, data:report);
	}
   else {
	 report = desc_over_ssl + '\n\nPlugin output:\n\nRemote telnet banner:\n' + banner;
         security_note(port:port, data:report);
 	}
  }
}

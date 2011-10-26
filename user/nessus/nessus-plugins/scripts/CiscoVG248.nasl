# Cisco VG248 with a blank password nasl script. - non intrusive
# This script was written by Rick McCloskey <rpm.security@gmail.com>
# 
# Tested against production systems with positive results. 
# This cisco unit does not respond to the other "Cisco with no password" 
# nasl scripts.
#
#
# This script is released under GPL
#

if(description)
{
   script_id(19377);
   script_version ("$Revision: 1.2 $");
   
   name["english"] = "Cisco VG248 login password is blank";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host is a Cisco VG248 with a blank password.

The Cisco VG248 does not have a password set and allows direct
access to the configuration interface. An attacker could telnet 
to the Cisco unit and reconfigure it to lock the owner out as 
well as completely disable the phone system. 

Solution : Telnet to this unit and at the configuration interface: 
Choose Configure-> and set the login and enable passwords. If 
possible, in the future do not use telnet since it is an insecure protocol.

Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "The remote host is a Cisco VG248 with a blank password.";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005 Rick McCloskey");
   script_family(english:"CISCO");
 
   exit(0);
}

include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if ( ! port ) port = 23;
if ( ! get_port_state(port)) exit (0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit (0);
 banner = telnet_negotiate(socket:soc);
 banner += line = recv_line(socket:soc, length:4096);
 n  = 0;
 while( line =~ "^ ")
	{
   		line = recv_line(socket:soc, length:4096);
		banner += line;
		n ++;
		if ( n > 100 ) exit(0); # Bad server ?
	}
   close(soc);
   if ( "Main menu" >< banner && "Configure" >< banner && "Display" >< banner )
	{
		security_hole(port);
	}
 
}


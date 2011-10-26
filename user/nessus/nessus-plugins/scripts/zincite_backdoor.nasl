#
# Copyright (C) 2004 Tenable Network Security
#
#

if(description)
{
 script_id(14184);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Zincite.A (MyDoom.M) Backdoor";

 script_name(english:name["english"]);
 
 desc["english"] = "
The backdoor 'BackDoor.Zincite.A' is installed on the remote host. It has
probably been installed by the 'MyDoom.M' virus.

This backdoor may allow an attacker to gain unauthorized access on the remote
host.

See also :  
http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.m@mm.html
Risk factor : Critical";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detect MyDoom worm";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(1034);
 exit(0);
}


port = 1034;
if ( get_port_state(port) ) 
 {
	req = raw_string(0xc7);
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:255, timeout:3);
        if ( raw_string(0x92, 0x3a, 0x6c) >< r && strlen(r) == 255 )	
	 security_hole(port);

	}
 }


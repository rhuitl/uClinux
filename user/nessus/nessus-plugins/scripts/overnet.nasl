#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11845);
 script_version("$Revision: 1.2 $");
 name["english"] = "Overnet P2P check";
 script_name(english:name["english"]);

 desc["english"] = "
The remote server seems to be a Overnet Peer-to-Peer client,
which may not be suitable for a business environment. 
 
Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote system is running Overnet";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 exit(0);
}




port = 5768;
if(!get_udp_port_state(port))exit(0);
req = raw_string(0xE3,0x0C,0xAB,0xA3,0xD7,0x95,0x39,0xE5,0x8C,0x49,0xEA,0xAB,0xEB,0x4F,0xA5,0x50,0xB8,0xF4,0xDD,0x9A,0x3E,0xD0,0x89,0x1F,0x00);
soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
if (r) security_warning(port);
exit(0);



#
#
# This script is (C) 2003 Renaud Deraison
#
#

if (description)
{
 script_id(11387);
 script_version ("$Revision: 1.3 $");
 script_name(english:"L2TP detection");
 desc["english"] = "
This host is running a L2TP server - it's probably a VPN endpoint.

Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running a L2TP (VPN) service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 exit(0);
}




req = raw_string(0xC8, 2, 0, 76, 0, 0, 0, 0,0,0,0,0,
		 0x80, 8, 0,0,0,0,0,1,
		 0x80, 8, 0,0,0,2,1,0,
		 0x80, 10,0,0,0,3,0,0,0,3,
		 0x80, 10,0,0,0,4,0,0,0,0,
		 0x80, 12,0,0,0,7) + "nessus" +
      raw_string(0x80, 8, 0,0,0,8,42,42,
                 0x80, 8, 0,0,0,10,0,4);
		 
soc = open_sock_udp(1701);
send(socket:soc, data:req);
r = recv(socket:soc, length:1024);
if(!r)exit(0);
close(soc);
if((ord(r[1]) & 0x0F) == 0x02){
	set_kb_item(name:"Services/udp/l2tp", value:1701);
	security_note(port:1701, proto:"udp");
	}

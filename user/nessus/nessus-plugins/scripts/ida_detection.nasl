#
# (C) Tenable Network Security
#
if(description)
{
 script_id(17258);
 script_version("$Revision: 1.4 $");
 name["english"] = "IDA Pro Detection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host seems to be running the IDA Pro Disassembler Program.

Solution : Filter incoming traffic to this port.
See also : http://www.datarescue.com/
Risk factor : None";

 script_description(english:desc["english"]);

 summary["english"] = "IDA Pro Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports(23945);
 exit(0);
}


port = 23945;

req = raw_string(0x49,0x44,0x41,0x00,0x01,0x00,0x00,0x00) + crap(32);
match = raw_string(0x49,0x44,0x41,0x00,0x00);
soc = open_sock_udp(port);
send (socket:soc, data:req);
r = recv(socket:soc, length:40, timeout:3);
if ( ! r ) exit(0);
if (match >< r)
	security_note(port);

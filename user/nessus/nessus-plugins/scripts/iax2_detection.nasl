#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
script_id(20834);
script_version("$Revision: 1.1 $");

name["english"] = "Inter-Asterisk eXchange Protocol Detection";
script_name(english:name["english"]);

desc["english"] = "
Synopsis :

The remote system is running a server that speaks the Inter-Asterisk
eXchange Protocol. 

Description :

The Inter-Asterisk eXchange protocol (IAX2) is used by the Asterisk
PBX Server and other IP Telephony clients/servers to enable voice
communication between them. 

See also :

http://en.wikipedia.org/wiki/IAX

Solution :

If possible, filter incoming connections to the port so that it is
used by trusted sources only. 

Risk factor :

None";

script_description(english:desc["english"]);

summary["english"] = "Checks if the remote system is running the IAX2 protocol";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_family(english:"Service detection");
script_copyright(english:"This script is Copyright (C) 2006 Ferdy Riphagen");
script_require_udp_ports(4569);
exit(0);
}

include("misc_func.inc");

port = 4569;
if (!get_udp_port_state(port)) exit(0);

# Open the socket but don't check the state of it.
soc = open_sock_udp(port);

# Generate the 'IAX2' poke packet.
poke_msg = raw_string(
        0x80, 0x00,		# IAX2 Full Packet Type
        0x00, 0x00,		# Destination Call
        0x00, 0x00, 0x00, 0x00,	# Timestamp
        0x00,               	# Outbound Seq No
        0x00,                   # Inbound Seq No
        0x06,                   # IAX Type
        0x1E);                  # IAX2 Poke Command

# Send the poke request.
send(socket:soc, data:poke_msg);

recv = recv(socket:soc, length:128);
if (recv == NULL) exit(0);

# Check if we get the right response. 
if (strlen(recv) != 12) exit(0);
if (ord(recv[10]) == 6 && 	# IAX Type 
   (ord(recv[11]) == 3 || 	# IAX PONG 
    ord(recv[11]) == 4))  {	# IAX ACK
  
 security_note(port);
 register_service(ipproto:"udp", proto:"iax2", port:port);
 exit(0);
}

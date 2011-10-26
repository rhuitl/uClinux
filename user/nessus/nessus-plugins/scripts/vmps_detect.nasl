#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host is running a server for assigning switch ports to
VLANs dynamically. 

Description :

The remote host is running a VLAN Management Policy Server (VMPS),
which is used for assigning switch ports to specific VLANs based on
the MAC address of connecting device. 

See also :

http://www.cisco.com/en/US/tech/tk389/tk814/tk839/tsd_technology_support_sub-protocol_home.html

Risk factor : 

None";


if (description) {
  script_id(20066);
  script_version("$Revision: 1.3 $");

  script_name(english:"VLAN Membership Policy Server Detection");
  script_summary(english:"Detects a VLAN Membership Policy Server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports(1589);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 1589;
if (!get_udp_port_state(port)) exit(0);


# Use a random domain to ensure we get a "WRONG DOMAIN" response.
domain = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
# Use a random sequence number to verify the response packet.
seq = rand_str(length:4);
# A request to join a port.
#
# nb: doc/VQP-spec.txt in the source has a description of the protocol.
req = raw_string(
  # Header
  0x01,                                 # constant
  0x01,                                 # VQP Request, Join Port
  0x00,                                 # action
  0x06,                                 # unknown, but used in requests
  seq,                                  # packet sequence number.

  # Data
  0x00, 0x00, 0x0c, 0x01,               # client IP address data
    0x00, 0x04,                         #   length
    0x7f, 0x00, 0x00, 0x01,             #   actual data (127.0.0.1)
  0x00, 0x00, 0x0c, 0x02,               # port name
    0x00, strlen("nessus"),             #   length
    "nessus",                           #   actual data
  0x00, 0x00, 0x0c, 0x03,               # VLAN name
    0x00, strlen(SCRIPT_NAME),          #   length
    SCRIPT_NAME,                        #   actual data
  0x00, 0x00, 0x0c, 0x04,               # VTP/VMPS domain name
    0x00, strlen(domain),               #   length
    domain,                             #   actual data
  0x00, 0x00, 0x0c, 0x07,               # unknown
    0x00, 0x01,                         #   length
    0x00,                               #   always zero?
  0x00, 0x00, 0x0c, 0x06,               # MAC
    0x00, 0x06,                         #   length
    0x12, 0x34, 0x12, 0x34, 0x12, 0x34  #   actual data
);


# Try to get a response out of the server.
soc = open_sock_udp(port);
if (!soc) exit(0);

send(socket:soc, data:req);

# Read the response.
res = recv(socket:soc, length:16);

# If we get a response...
if (!isnull(res)) {
  # If it looks like a VMPS daemon because...
  if (
    # the first byte is 1 and...
    ord(res[0]) == 1 &&
    # the second byte indicates it's a VQP response and...
    ord(res[1]) == 2 &&
    # the third byte indicates it's the wrong domain and..
    ord(res[2]) == 5 &&
    # the sequence number matches what we sent.
    substr(res, 4, 7) == seq
  ) {
    # Register and report the service.
    register_service(port:port, ipproto:"udp", proto:"vmps");
    security_note(port:port, protocol:"udp", data:desc);
  }
}

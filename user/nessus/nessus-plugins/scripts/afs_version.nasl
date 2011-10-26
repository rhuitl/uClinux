#
# This script was written by Lionel Cons <lionel.cons@cern.ch>, CERN


#
#
# description
#
if (description)
{
  script_id(10441);
 script_version ("$Revision: 1.9 $");
  name["english"] = "AFS client version";
  script_name(english:name["english"]);

  desc["english"] = "
This detects the AFS client version by connecting
to the AFS callback port and processing the buffer received.
The client version gives potential attackers additional information about the
system they are attacking. Versions and types should be omitted
where possible.

Solution: None.

Risk factor : Low";

  script_description(english:desc["english"]);

  summary["english"] = "AFS client version";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) CERN");

  family["english"] = "General";
  script_family(english:family["english"]);
  exit(0);
}

#
# script
#
port = 7001;
if(!(get_udp_port_state(port)))exit(0);
sock = open_sock_udp(port);
if (sock) {
  data = raw_string(0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x0d, 0x05, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:sock, data:data);
  max = 80;
  info = recv(socket:sock, length:max);
  if (strlen(info) > 28) {
    data = "AFS version: ";
    for (i = 28; i < max; i = i + 1) {
      if (info[i] == raw_string(0x00)) {
        i = max;
      } else {
        data = data + info[i];
      }
    }
    security_note(port:port, protocol:"udp", data:data);
  }
  close(sock);
}

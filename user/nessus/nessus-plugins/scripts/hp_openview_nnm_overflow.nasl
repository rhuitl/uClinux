#
# (C) Tenable Network Security
#

if (description) {
  script_id(19707);
  script_cve_id("CVE-2005-1056");
  script_bugtraq_id(13029);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15321");
  }
  script_version("$Revision: 1.5 $");

  name["english"] = "HP OpenView NNM multiple services Heap Overflow";
  script_name(english:name["english"]);
  
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the
HP OpenView Topology Manager Daemon. 

Description :

The remote host is running HP OpenView Topology Manager Daemon for IP
discovery and layout. 

The remote version of this software is vulnerable to a Heap Overflow
vulnerability. 

An unauthenticated attacker can exploit this flaw by sending a
specialy crafted packet to the remote host.  A successful exploitation
of this vulnerability would result in remote code execution with the
privileges of the daemon itself. 

Note that other OV NNM services are vulnerable this flaw as well. 

See also :

http://www.securityfocus.com/advisories/8372

Solution : 

Install one of the patches listed in the advisory referenced above. 

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HP OpenView NNM Heap Overflow";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_dependencie("hp_openview_ovtopmd.nasl");
  script_require_ports(2532);
  exit(0);
}

include ("misc_func.inc");

port = get_kb_item('Services/ovtopmd');
if (!port) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

req = raw_string (0x00,0x00,0x3F,0xFD,0x54,0x4E,0x53) + crap(data:raw_string(0), length:0x3FFA);

send (socket:soc, data:req);
buf = recv(socket:soc, length:16);

if ("0000000c000000020000000100000000" >< hexstr(buf))
{
  security_hole(port);
}

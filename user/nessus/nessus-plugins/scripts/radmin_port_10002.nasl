#
# (C) Tenable Network Security
# Based on radmin_detect.nasl, by Michel Arboi
#



if(description)
{
  script_id(14834);
  if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0028");
  script_version ("$Revision: 1.4 $");
  script_cve_id("CVE-2004-0200");
 
  script_name(english:"radmin on port 10002 - possible GDI compromise");
 
  desc["english"] = "
The remote host is running radmin - a remote administration tool - on port
10002.

This probably indicates that an attacker exploited one of the flaws described 
in MS04-028 with a widely available exploit.

As a result, anyone may connect to the remote host and gain its control by 
logging into the remote radmin server.

See also : http://www.easynews.com/virus.txt
Solution : Re-install this host, as it has been compromised
Risk factor : Critical";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect radmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
  family["english"] = "Backdoors";
  script_family(english:family["english"]);
  script_require_ports(10002);

  exit(0);
}

port = 10002;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x08);
send(socket: soc, data: req);
r = recv(socket: soc, length: 6);
close(soc);
xp1 = "010000002500";
xp2 = "010000002501";


if (( xp1 >< hexstr(r) ) || ( xp2 >< hexstr(r) ))
{
        security_hole(port);
	exit(0);
}



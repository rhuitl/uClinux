#
# (C) Tenable Network Security
#


if (description) {
  script_id(18257);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1009", "CVE-2005-1547");
  script_bugtraq_id(12967, 13594, 13618);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16602");
  }

  name["english"] = "BakBone NetVault Remote Heap Overflow Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote backup server is affected by multiple overflow flaws. 

Description :

The installed version of BakBone NetVault on the remote host suffers
from two remote heap buffer overflow vulnerabilities.  An attacker may
be able to exploit this flaw and execute arbitrary code with SYSTEM
privileges on the affected machine. 

See also : 

http://www.hat-squad.com/en/000164.html
http://archives.neohapsis.com/archives/bugtraq/2005-05/0133.html
http://archives.neohapsis.com/archives/bugtraq/2005-05/0167.html
http://www.bakbone.com/docs/NetVault_Release_Notes_(712).pdf
http://www.bakbone.com/docs/NetVault_Release_Notes_(731).pdf

Solution : 

Upgrade to BackBone NetVaule 7.1.2 / 7.3.1 or later.

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote heap overflow vulnerabilities in BakBone NetVault";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 20031);

  exit(0);
}


include("misc_func.inc");


if ( !safe_checks() )
{
port = get_unknown_svc(20031);
if (!port) exit(0);
}
else port = 20031;

if (!get_port_state(port)) exit(0);


# Connect to the port and send an initial packet.
soc = open_sock_tcp(port);
if (!soc) exit(0);

grabcpname = 
  raw_string(
    0xC9, 0x00, 0x00, 0x00, 0x01, 0xCB, 0x22, 0x77,
    0xC9, 0x17, 0x00, 0x00, 0x00, 0x69, 0x3B, 0x69,
    0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 
    0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 0x3B, 0x69, 
    0x3B, 0x73, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00
  ) +
  crap(data:raw_string(0x90), length:10) +
  crap(data:raw_string(0x00), length:102) +
  raw_string(0x09) +
  crap(data:raw_string(0x00), length:8);
send(socket:soc, data:grabcpname);
res = recv(socket:soc, length:1024);
close(soc);
if (res == NULL) exit(0);
len = strlen(res);


# If the response packet looks like it's from NetVault...
if (len >= 400 && ord(res[13]) == 105 && ord(res[14]) == 59) {
  # Get the version number of NetVault on the remote.
  ver = string(res[len-37], ".", res[len-35], ".", res[len-34]);

  if (ver =~ "^(6\.|7\.(0\.|1\.[01]|3\.0))") security_hole(port);
}

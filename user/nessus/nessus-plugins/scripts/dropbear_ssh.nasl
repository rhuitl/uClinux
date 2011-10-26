#
# (C) Tenable Network Security
#
if (description) {
  script_id(14234);
  script_version("1.9");

  script_cve_id("CVE-2004-2486");
  script_bugtraq_id(10803);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"8137");
  }

  name["english"] = "Dropbear remote DSS SSH vuln";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Dropbear prior to version 0.43.  
There is a flaw in this version of Dropbear which would
enable a remote attacker to gain control of the system
from a remote location.

Solution : Upgrade to at least version 0.43 of Dropbear. 

See also : http://matt.ucc.asn.au/dropbear/CHANGES
 
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Dropbear remote DSS SSH vuln check";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) Tenable Network Security");
  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);

  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");
  exit(0);
}



port = get_kb_item ("Services/ssh"); 
if (!port) port = 22;
if (!get_port_state (port)) exit (0);

banner = get_kb_item("SSH/banner/" + port );

if (! banner) exit(0);

# version 0.28 thru 0.42 are vulnerable
if (egrep(string:banner, pattern:"-dropbear_0\.(2[0-9]|3[0-9]|4[0-2])") )
	security_hole(port);


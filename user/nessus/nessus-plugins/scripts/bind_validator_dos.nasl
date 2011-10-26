#
# This script is (c) Tenable Network Security
#

if(description)
{
 script_id(16261);
 script_bugtraq_id(12365, 12497);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0034");
 
 name["english"] = "BIND Validator Self Checking Remote Denial Of Service Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its version number, has
a flaw in the way 'authvalidator()' is implemented.

An attacker may be able to launch a Denial of service attack
against the remote service.

Solution : Upgrade to bind 9.3.1.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

include('global_settings.inc');

if (report_paranoia < 1) exit(0);	# FP on Mandrake

vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if (ereg(string:vers, pattern:"^9\.3\.0$"))
  security_hole(port: 53, proto: 'udp');

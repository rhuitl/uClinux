#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16126);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(12227);

 name["english"] = "HylaFAX Remote Access Control Bypass Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running HylaFAX, a fax transmission software.

It is reported that HylaFAX is prone to an access control bypass
vulnerability. An attacker, exploiting this flaw, may be able to gain
unauthorized access to the service.

Solution : Upgrade to version 4.2.1 or later
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if HylaFAX is vulnerable to access control bypass.";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_require_ports(4559);
 exit(0);
}

port = 4559;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (egrep(pattern:"^220.*\(HylaFAX \(tm\) Version ([0-3]\.|4\.([0-1]\.|2\.0))", string:r))
 {
 security_hole(port);
 exit(0);
 }

#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17631);
 script_cve_id("CVE-2005-0876", "CVE-2005-0877");
 script_bugtraq_id(12897);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "dnsmasq Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running dnsmasq, a DHCP and DNS server.

The remote version of this software is vulnerable to multiple remote
vulnerabilities which may allow an attacker to execute arbitrary code on
the remote host or perform a DNS cache poisoning attack.

Solution : Upgrade to dnsmasq 2.21.0 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of dnsmasq"; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}



# dnsmasq replies to BIND.VERSION
vers = get_kb_item("bind/version");
if ( vers && ereg(pattern:"dnsmasq-([01]\.|2\.([0-9]$|1[0-9]$|20))", string:vers) )
	security_hole(port:53, proto:"udp");

#
# This script is (c) Tenable Network Security
#

if(description)
{
 script_id(16260);
 script_bugtraq_id(12364);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0033");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0005");

 
 name["english"] = "ISC BIND Q_UseDNS Remote Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its version number, is
vulnerable to a buffer overflow into the 'q_usedns' buffer.

An attacker may be able to launch a Denial of service attack
against the remote service.

Solution : upgrade to bind 8.4.6
Risk factor : High
See also : http://www.kb.cert.org/vuls/id/327633";

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

vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if (ereg(string:vers, pattern:"^8\.4\.[4-5]$") )
  security_hole(53);

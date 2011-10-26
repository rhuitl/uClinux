#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17158);
 script_cve_id("CVE-2005-0491");
 script_bugtraq_id(12594);
 script_version("$Revision: 1.4 $");

 name["english"] = "Knox Arkeia Type 77 Request Remote Buffer Overrun";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Arkea Network Backup agent, an agent system
designed to remotely perform backups of the remote host.

The remote version of this agent contains a buffer overflow vulnerability
which may allow an attacker to execute arbitrary commands on the remote
host with the privileges of the arkeia daemon.

Solution : Upgrade to Arkeia 5.3.5, 5.2.28 our 5.1.21
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number of the remote arkeia daemon";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 
 script_require_ports(617);
 script_dependencie("arkeia_default_account.nasl");
 exit(0);
}



version =  get_kb_item("arkeia-client/617");
if ( ! version ) exit(0);
if ( ereg(pattern:"^([0-4]\.|5\.0|5\.1\.([0-9](1?[^0-9]|$)|20)|5\.2\.(1?[0-9]([^0-9]|$)|2[0-7])|5\.3\.[0-4]([^0-9]|$))", string:version))
	security_hole(617);

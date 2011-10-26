#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Wally Whacker <whacker@hackerwhacker.com>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14660);
 script_bugtraq_id(1137);
 script_cve_id("CVE-2000-0339");  
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"1294");

 script_version("$Revision: 1.4 $");

 name["english"] = "ZoneAlarm Personal Firewall port 67 flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
ZoneAlarm firewall runs on this host.

This version contains a flaw that may allow a remote attacker to bypass 
the ruleset. 
The issue is due to ZoneAlarm not monitoring and alerting UDP traffic with a 
source port of 67. 

This allows an attacker to bypass the firewall to reach protected hosts without 
setting off warnings on the firewall.

Solution : Upgrade at least to version 2.1.25
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check ZoneAlarm version";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl","zone_alarm_local_dos.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport", "zonealarm/version");

 script_require_ports(139, 445);
 exit(0);
}

zaversion = get_kb_item ("zonealarm/version");
if (!zaversion) exit (0);

if(ereg(pattern:"[0-1]\.|2\.0|2\.1\.([0-9]|1[0-9]|2[0-4])[^0-9]", string:zaversion))
{
 security_hole(0);
}

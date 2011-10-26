#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16274);
 script_cve_id("CVE-2005-0199");
 script_bugtraq_id(12397);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "ngIRCd Remote Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the ngIRCd service which may
be vulnerable to a buffer overflow in the way the server handle list
names.

An attacker may execute code on the remote host by using a malicious
user information.

Solution : Upgrade to ngIRCd 0.8.2 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ngircd-0\.([0-7]\.|8\.[0-1][^0-9]).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}



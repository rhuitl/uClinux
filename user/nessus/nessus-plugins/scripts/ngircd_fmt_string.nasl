#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16310);
 script_cve_id("CVE-2005-0226");
 script_bugtraq_id(12434);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "ngIRCd Format String Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the ngIRCd service which is
be vulnerable to a format string vulnerability which may allow an attacker
to execute arbitrary code on the remote host.

An attacker may execute code on the remote host by using a malicious
user information.

Solution : Upgrade to ngIRCd 0.8.3 (when available) 
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencie("ircd.nasl");
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

if(egrep(pattern:".*ngircd-0\.([0-7]\.|8\.[0-2][^0-9]).*", string:banner)) 
{
 security_hole(port);
 exit(0);
}



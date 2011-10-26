#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18291);
 script_bugtraq_id(13656, 13654);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "IgnitionServer Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the IgnitionServer IRC 
service which contains a bug in the way it handles locked channels, as
well as a design error regarding the access validation checks.

An attacker may use this flaw to block an IRC operator out of a protected
channel. A host may use this flaw to delete an entry created by a owner.

Solution : Upgrade to IgnitionServer 0.3.6-P1 or newer
Risk factor : Low";


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

if(egrep(pattern:".*ignitionServer 0\.([0-2]\.|3\.[0-5][^0-9]|3\.6[^-]).*", string:banner)) 
 security_note(port);


#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14376);
 script_bugtraq_id(11041);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "IgnitionServer Denial of Service";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the IgnitionServer IRC 
service which may be vulnerable to a denial of service in the SERVER
command.

An attacker may crash the remote host by misusing the SERVER command
repeatdly.

Solution : Upgrade to IgnitionServer 0.3.2 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if(egrep(pattern:".*ignitionServer 0\.([0-2]\.|3\.[01][^0-9]).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}


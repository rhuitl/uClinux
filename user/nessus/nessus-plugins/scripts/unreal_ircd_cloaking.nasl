#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12297);
 script_bugtraq_id(10663);
 script_cve_id("CVE-2004-0679");
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Unreal IRCd IP cloaking weakness";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Unreal IRCD, a popular IRC server.

The remote version of this server offers an 'IP cloaking' capability which
offers to hide the IP address of the users connected to the server, in
order to preserve their anonymity.

There is a design error in the algorithm used by the server which may
allow an attacker to guess the real IP address of another user of the server,
by reducing the number of tries to 2,000.

Solution : Upgrade to UnrealIRCD 3.2.1
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
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

# Unreal ircd
if(egrep(pattern:".*Unreal3\.(0\.|1\.[01][^0-9])", string:banner))
{
 security_warning(port);
 exit(0);
}


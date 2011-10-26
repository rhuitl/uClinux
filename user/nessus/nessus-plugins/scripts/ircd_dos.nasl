#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11797);
 script_bugtraq_id(8131);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "IRCd OperServ Raw Join DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of ircd which may crash
when it receives certain raw messages.

An attacker may use this flaw to disable this service remotely.

Solution : Upgrade to UnrealIRCD 3.2 beta17 or 3.1.6
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

# Unreal ircd
if(egrep(pattern:".*Unreal3\.((1\.[0-5][^0-9])|2-beta([0-9][^0-9]|1[0-6]))", string:banner))
{
 security_hole(port);
 exit(0);
}

# Unreal ircd
if(egrep(pattern:".*Unreal3\.((1\.[0-5][^0-9])|2-beta([0-9][^0-9]|1[0-6]))", string:banner))
{
 security_hole(port);
 exit(0);
}

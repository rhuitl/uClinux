#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11783);
 script_bugtraq_id(8038);
 script_cve_id("CVE-2003-0478");
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Multiple IRC daemons format string attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of ircd which may be vulnerable
to a format string attack.

An attacker may use this flaw to execute arbitrary code on this
host, or simply to disable this service remotely.

Solution : Upgrade to one of the following IRC daemon :
	andromede.net AndromedeIRCd 1.2.4
	DALnet Bahamut IRCd 1.4.36
	digatech digatech IRCd 1.2.2
	methane methane IRCd 0.1.2
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

if(egrep(pattern:".* bahamut-(0\.|1\.[0-3][^0-9]|1\.4.([0-9][^0-9]|[0-2][0-9]|3[0-5]))", string:banner))
{
 security_hole(port);
 exit(0);
}

# : AndromedeIRCd-1.3(00). 

if(egrep(pattern:".*AndromedeIRCd-(0\.|1\.[0-2][^0-9])", string:banner))
{
 security_hole(port);
 exit(0);
}

# digatech(sunrise)-1.2(03)

if(egrep(pattern:".*digatech[^0-9]*-(0\.|1\.[01][^0-9]|1\.2.(0[0-2]))", string:banner))
{ 
 security_hole(port);
 exit(0);
}

# ????
if(egrep(pattern:".*methane.*0\.(0.*|(1\.[0-2]))[^0-9]", string:banner, icase:TRUE))
{
 security_hole(port);
 exit(0);
}

# 

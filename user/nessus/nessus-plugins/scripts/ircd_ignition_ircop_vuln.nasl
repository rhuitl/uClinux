#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: vendor
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(14388);
 script_cve_id("CVE-2004-2553");
 script_bugtraq_id(9783);
 if ( defined_func("script_xref") )
 {
        script_xref(name:"OSVDB", value:"4121");
 }
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "IgnitionServer Irc operator privilege escalation vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the IgnitionServer IRC 
service which may be vulnerable to a flaw that let remote attacker
to gain elevated privileges on the system.

A remote attacker, who is an operator, can supply an unofficial command 
to the server to obtain elevated privileges and become a global IRC operator.

Solution : Upgrade to IgnitionServer 0.2.1-BRC1 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the version of the remote ircd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#the code

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([01]\.|2\.0).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}


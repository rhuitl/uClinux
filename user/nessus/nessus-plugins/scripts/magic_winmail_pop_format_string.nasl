#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11742);
 script_bugtraq_id(7667);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0391");
 
 name["english"] = "Magic WinMail Format string";
 script_name(english:name["english"]);
 
 desc["english"]  = "
The remote Winmail POP server, according to its banner, is
vulnerable to a format string attack when processing
the USER command.

An attacker may use this flaw to execute arbitrary
code on this host.

Solution : Upgrade to version WinMail 2.4 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Magic WinMail banner check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "Gain a shell remotely";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
    if(ereg(pattern:".*Magic Winmail Server (1\..*|2\.[0-3][^0-9])", string:banner, icase:TRUE))
    {
	security_hole(port);
    }
}

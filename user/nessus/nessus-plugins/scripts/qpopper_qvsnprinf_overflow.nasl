#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11376);
 script_bugtraq_id(7058);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0143");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:018");

 
 name["english"] = "qpopper Qvsnprintf buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"]  = "
The remote qpopper server, according to its banner, is
vulnerable to a one-byte overflow it its function
Qvsnprintf(). 

An attacker may use this flaw to gain a (non-root)
shell on this host, provided that he has a valid
POP account to log in with.

*** This test could not confirm the existence of the
*** problem - it relied on the banner being returned.

Solution : Upgrade to version 4.0.5cf2 or newer

Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "qpopper options buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 
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
    if(ereg(pattern:".*Qpopper.*version 4\.0\.[0-4][^0-9].*", string:banner, icase:TRUE))
    {
	security_hole(port);
    }
}
exit(0);

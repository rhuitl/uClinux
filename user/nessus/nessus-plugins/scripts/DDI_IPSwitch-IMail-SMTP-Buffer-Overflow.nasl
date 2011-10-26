#
# This script is Copyright (C) 2002 Digital Defense Inc.
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


if(description)
{
	script_id(10994);
	script_bugtraq_id(2083, 2651);
	script_version ("$Revision: 1.6 $");
	script_cve_id("CVE-2001-0039","CVE-2001-0494");

 
 	name["english"] = "IPSwitch IMail SMTP Buffer Overflow";
 	script_name(english:name["english"]);
 
	desc["english"] = "
A vulnerability exists within IMail that
allows remote attackers to gain SYSTEM level
access to servers running IMail's SMTP
daemon (versions 6.06 and below). The
vulnerability stems from the IMail SMTP daemon 
not doing proper bounds checking on various input 
data that gets passed to the IMail Mailing List 
handler code. If an attacker crafts a special 
buffer and sends it to a remote IMail SMTP server 
it is possible that an attacker can remotely execute 
code (commands) on the IMail system. 

Solution:
Download the latest patch from
http://ipswitch.com/support/IMail/patch-upgrades.html
Risk factor : Medium";

	script_description(english:desc["english"]);
 	summary["english"] = "IPSwitch IMail SMTP Buffer Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002 Digital Defense, Inc.");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_dependencie("find_service.nes");
	script_require_ports(25);
	exit(0);
}

debug = 0;
ddidata = string("Not Applicable");
port = 25;

if(get_port_state(port))
{
	if(debug == 1) { display("Port ", port, " is open.\n"); }
		

	soc = open_sock_tcp(port);
	if(soc)
	{
		if(debug == 1)
		{
			display("Socket is open.\n");
		}
		
		banner = recv_line(socket:soc, length:4096);
		
		if(debug == 1)
		{
			display("\n---------Results from request ---------\n");
			display(banner);
			display("\n---------End of Results from request ---------\n\n");
		}
		     
		if(
		   egrep(pattern:"IMail 6\.0[1-6] ", string:banner) 	|| 
		   egrep(pattern:"IMail 6\.0 ", string:banner) 		||
		   egrep(pattern:"IMail [1-5]\.", string:banner)
		  )
		{
			if(debug == 1)
			{
				display("SMTP Server is Imail\n");
			}
		
			security_note(port); 
			exit(0);
		}

		close(soc);
	}
	else
	{
		if(debug == 1) { display("Error: Socket didn't open.\n"); }
	}
}




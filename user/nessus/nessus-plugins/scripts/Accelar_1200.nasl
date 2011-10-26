#
# This script was written by Charles Thier <cthier@thethiers.net>
#
# GPLv2
#


if(description)
{
    script_id(18415);
    script_version("$Revision: 1.3 $");
    script_cve_id("CVE-1999-0508");
    name["english"] = "Bay Networks Accelar 1200 Switch found with default password";
    script_name(english:name["english"]);
 
   desc["english"] = "
The remote host appears to be an Bay Networks Accelar 1200 Switch with
its default password set.

The attacker could use this default password to gain remote access
to your switch.  This password could also be potentially used to
gain other sensitive information about your network from the switch.

Solution : Telnet to this switch and change the default password.
Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into Bay Networks switches with default password";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005 Charles Thier");
   script_family(english:"Misc.");
   script_require_ports(23);
   exit(0);
}


#
# The script code starts here
#

include("telnet_func.inc");
usrname = string("rwa\r\n");
password = string("rwa\r\n");

port = 23;
if(get_port_state(port))
{
	tnb = get_telnet_banner(port:port);
	if ( ! tnb ) exit(0);
        if ("Accelar 1200" >< tnb)
        {
                soc = open_sock_tcp(port);
                if(soc)
                {
                        answer = recv(socket:soc, length:4096);
                        if("ogin:" >< answer)
                        {
                                send(socket:soc, data:usrname);
                                answer = recv(socket:soc, length:4096);
                                send(socket:soc, data:password);
                                answer = recv(socket:soc, length:4096);
                                if("Accelar-1200" >< answer)
                                {
                                        security_hole(port:23);
                                }
                        }
                close(soc);
                }

        }
}



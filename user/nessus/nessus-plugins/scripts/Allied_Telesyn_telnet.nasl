#
#
# This script was written by Charles Thier <cthier@thethiers.net>
#
# GPLv2
#


if(description)
{
    script_id(18414);
    script_version("$Revision: 1.3 $");
    script_cve_id("CVE-1999-0508");
    name["english"] = "Allied Telesyn Router/Switch found with default password";
    script_name(english:name["english"]);
 
   desc["english"] = "
The Allied Telesyn Router/Switch has the default password set.

The attacker could use this default password to gain remote access
to your switch or router.  This password could also be potentially used to
gain other sensitive information about your network from the device.

Solution : Telnet to this Router/Switch and change the default password.

Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into Allied Telesyn routers and switches with default password";
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
usrname = string("manager\r\n");
password = string("friend\r\n");

port = 23;
if(get_port_state(port))
{
tnb = get_telnet_banner(port:port);
        if ("TELNET session" >< tnb)
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
                                if("Manager" >< answer)
                                {
                                        security_hole(port:23);
                                }
                        }
                close(soc);
                }

        }
}


#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10998);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0508");
 
 
 name["english"] = "Shiva LanRover Blank Password";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The Shiva LanRover has no password set for the
root user account. An attacker is able to telnet
to this system and gain access to any phone lines
attached to this device. Additionally, the LanRover
can be used as a relay point for further attacks
via the telnet and rlogin functionality available
from the administration shell.

Solution: Telnet to this device and change the 
password for the root account via the passwd
command. Please ensure any other accounts have
strong passwords set.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a blank password for the root account.";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Incorporated",
		francais:"Ce script est Copyright (C) 2002 Digital Defense Incorporated");

 family["english"] = "Misc.";
 family["francais"] = "Divers";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "@ Userid:" >!< r ) exit(0);

soc = open_sock_tcp(port);

if(soc)
{
    r = telnet_negotiate(socket:soc);

    if("@ Userid:" >< r)
    { 
        send(socket:soc, data:string("root\r\n"));
        r = recv(socket:soc, length:4096);
        
        if("Password?" >< r)
        {
            send(socket:soc, data:string("\r\n"));
            r = recv(socket:soc, length:4096);

            if ("Shiva LanRover" >< r)
            {
                security_hole(port:port);
            }
       }
    }
    close(soc);
}

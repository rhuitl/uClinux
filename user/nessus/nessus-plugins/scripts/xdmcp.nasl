#
# This script was written by Pasi Eronen <pasi.eronen@nixu.com>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10891);
#script_cve_id("CVE-MAP-NOMATCH");
 script_version("$Revision: 1.6 $");
 name["english"] = "X Display Manager Control Protocol (XDMCP)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running XDMCP.

This protocol is used to provide X display connections for X terminals. 
XDMCP is completely insecure, since the traffic and passwords are not 
encrypted. 

An attacker may use this flaw to capture all the keystrokes of the users 
using this host through their X terminal, including passwords.

Also XDMCP is an additional login mechanism that you may not have been 
aware was enabled, or may not be monitoring failed logins on.

Solution : Disable XDMCP
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if XDM has XDMCP protocol enabled";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Pasi Eronen");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#

# this magic info request packet
req = raw_string(0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00);

if(!get_udp_port_state(177))exit(0);

soc = open_sock_udp(177);

if(soc)
{
        send(socket:soc, data:req);
        result  = recv(socket:soc, length:1000);
        if (result && (result[0] == raw_string(0x00)) &&
            (result[1] == raw_string(0x01)) &&
            (result[2] == raw_string(0x00))) {
                security_warning(port:177, protocol:"udp");
        }
}

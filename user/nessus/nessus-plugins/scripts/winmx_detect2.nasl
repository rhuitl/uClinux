#
# (C) Tenable Network Security
#

# there is already a nice WinMX check by Nessus...however, it relies on registry read access...this check
# works even without registry access...the anomaly is that when you connect to a WinMX client on port 6699
# immediatly after the handshake, the client send a PSH packet with a single byte of data set to "1"

if(description)
{
 script_id(11847);
 script_version("$Revision: 1.4 $");
#  script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "WinMX P2P check";
 script_name(english:name["english"]);

 desc["english"] = "
The remote server seems to be a WinMX Peer-to-Peer client,
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote system is running WinMX";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 exit(0);
}




port = 6699;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
r = recv(socket:soc, min:1, length:256);
if ( strlen(r) == 1 && r == "1" ) security_warning(port);
exit(0);

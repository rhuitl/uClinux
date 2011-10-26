#
# (C) Tenable Network Security
#
# there is already a nice Kazaa check by Nessus...however, it relies on registry read access...this check
# works even without registry access...

if(description)
{
 script_id(11844);
 script_bugtraq_id(7680);
 script_version("$Revision: 1.6 $");
 name["english"] = "Kazaa P2P check";
 script_name(english:name["english"]);
 script_cve_id("CVE-2003-0397");
 desc["english"] = "
The remote server seems to be a Kazaa Peer-to-Peer client, 
which may not be suitable for a business environment. 

In addition, there is rumoured to be a remote exploit against Kazaa clients up to 2.0.2.  While this has not been confirmed, the reporting sources are credible.

Solution : Uninstall this software
Risk factor : Low";


 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote system is running Kazaa";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);

 exit(0);
}




port = 6699;
if(!get_udp_port_state(port))exit(0);
req = raw_string(0x27,0x00,0x00,0x00,0xA9,0x80,0x4B,0x61,0x5A,0x61,0x41,0x00);
soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
if (strlen(r) == 21) security_warning(port);
exit(0);




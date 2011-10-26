# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10942);
 script_bugtraq_id(7276);
 script_version("$Revision: 1.7 $");
 name["english"] = "Check for a Citrix server";
 script_name(english:name["english"]);

 desc["english"] = "
A Citrix server is running on this machine.

Citrix servers allow a Windows user to remotely
obtain a graphical login (and therefore act as a local
user on the remote host). 

NOTE: by default the Citrix Server application 
utilizes a weak 40 bit obfuscation algorithm (not
even a true encryption).  If the default settings have
not been changed, there already exists tools which can
be used to passively ferret userIDs and passwords as they
traverse a network.

If this server is located within your DMZ, the risk is
substantially higher, as Citrix necessarily requires
access into the internal network for applications like
SMB browsing, file sharing, email synchronization, etc.

If an attacker gains a valid login and password, he may
be able to use this service to gain further access on
the remote host or remote network. This protocol has also
been shown to be  vulnerable to a man-in-the-middle attack.

Solution: Disable this service if you do not use it. Also, make sure
that the server is configured to utilize strong encryption. 

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "CITRIX check";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_require_ports(1494);
 exit(0);
}

#
# The script code starts here
#





function check_setting(port) {
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(soc) {
    r = recv(socket:soc, length:64);
    if ((egrep(pattern:".*ICA.*", string:r))) {
        security_note(port);
    }
    close(soc);
 }
}

port = 1494;
check_setting(port:port);

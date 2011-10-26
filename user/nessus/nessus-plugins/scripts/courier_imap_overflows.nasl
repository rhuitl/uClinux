#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12103);
 script_bugtraq_id(10976, 9845);
 script_cve_id("CVE-2004-0777");
 script_version("$Revision: 1.6 $");
 
 name["english"] = "Courier IMAP remote overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote mail server is the Courier-IMAP imap server. 

There is a buffer overflow in the conversions functions of this software
which may allow an attacker to execute arbitrary code on this host.

Solution : Upgrade to Courier-Imap 3.0.0 or newer
Risk factor : High";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if (!  port ) port = 143;

banner = get_kb_item(string("imap/banner/", port));
if(!banner)
 {
  if(get_port_state(port))
  { 
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
   set_kb_item(name:"imap/banner/" + port, value:banner);
   close(soc);
  }
 }

if(banner)
{
 if ( "OK Courier-IMAP ready." >< banner ) security_hole(port);
}

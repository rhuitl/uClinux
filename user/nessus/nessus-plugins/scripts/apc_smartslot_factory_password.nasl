#
# (C) Tenable Network Security
#
# Refs:
#  Subject: APC 9606 SmartSlot Web/SNMP management card "backdoor"
#   From: Dave Tarbatt <bugtraq@always.sniffing.net>
#   To: bugtraq@securityfocus.com
#   Date: 16 Feb 2004 11:24:32 +0000
#

if(description)
{
 script_id(12066);
 script_cve_id("CVE-2004-0311");
 script_bugtraq_id(9681);
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"APC SmartSlot factory account");
	     

 desc["english"] = "
The remote APC device can be accessed by telnet with any username and the
factory password 'TENmanUFactOryPOWER'.

An attacker may use this flaw to gain access on this device.

Solution: Disable telnet on this device
Risk factor: High";

 script_description(english:desc["english"]);
		 
script_summary(english:"Logs into the remote host");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Default Unix Accounts");
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here : 
#

include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   banner =  get_telnet_banner(port:port);
   if ( "User Name :" >!< buf ) exit(0);

   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if ("User Name :" >< buf)
         {
            data = string("*\r\n");
            send(socket:soc, data:data);
            buf = recv_line(socket:soc, length:1024);
	    if ( "Password" >!< buf ) exit(0);
	    send(socket:soc, data:'TENmanUFactOryPOWER\r\n');
	    buf = recv(socket:soc, length:4096);
	    if ("Factory Menu" >< buf  ||
		"Final Functional Test" >< buf ) security_hole(port);
         }
    close(soc);
   }
}


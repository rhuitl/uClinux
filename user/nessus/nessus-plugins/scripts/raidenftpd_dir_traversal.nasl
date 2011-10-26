#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: joetesta@hushmail.com 
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18224);
 script_bugtraq_id(2655);
 script_version ("$Revision: 1.2 $");

 name["english"] = "RaidenFTPD Directory Traversal flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the RaidenFTPD FTP server.

The remote version of this software is vulnerable to a directory traversal flaw.
A malicious user could exploit it to gain read and write access to the outside 
of the intended ftp root.

Solution : Upgrade to 2.1 build 952 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects RaidenFTPD Directory Traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "FTP";
 script_family(english:family["english"]);
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

if ( !login || ! password ) exit(0);


if(get_port_state(port))
{
 banner = get_ftp_banner(port: port);
 if ( ! banner ) exit(0);
 if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
	ftp_recv_line(socket:soc);
       if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("GET ....\....\autoexec.bat\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("150 Sending " >< r) security_warning(port);
	      }
       close(soc);
  }
}
exit(0);

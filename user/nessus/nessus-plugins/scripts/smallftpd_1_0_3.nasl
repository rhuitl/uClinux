#
# This script was written by Audun Larsen <larsen@xqus.com>
#

if(description)
{
 script_id(12072);
 script_cve_id("CVE-2004-0299");
 script_bugtraq_id(9684);
 script_version("$Revision: 1.7 $");
 name["english"] = "smallftpd 1.0.3";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be running smallftpd 1.0.3

It has been reported that SmallFTPD is prone to a remote denial of service 
vulnerability. This issue is due to the application failing to properly 
validate user input. 

Solution : Use a different FTP server.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of smallftpd";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
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
  data = ftp_recv_line(socket:soc);
  if(data)
  {
   if(egrep(pattern:"^220.*smallftpd (0\..*|1\.0\.[0-3][^0-9])", string:data) )
   {
    security_warning(port);
   }
  }
 }
}

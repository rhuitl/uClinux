#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Modified by rd to use get_ftp_banner() and be solely banner-based

if(description)
{
 script_id(12082);
 script_bugtraq_id(9729);
 script_version("$Revision: 1.2 $");
 name["english"] = "RobotFTP DoS";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be running RobotFTP.

RobotFTP server has been reported prone to a denial of service vulnerability.
The issue presents itself when certain commands are sent to the service,
before authentication is negotiated.

The following versions of RobotFTP are vulnerable:
RobotFTP RobotFTP Server 1.0
RobotFTP RobotFTP Server 2.0 Beta 1
RobotFTP RobotFTP Server 2.0

Solution : Use a different FTP server 
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of RobotFTP";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
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
 banner  = get_ftp_banner(port:port);
 if ( ! banner ) exit(0);
 if ( egrep(pattern:"^220.*RobotFTP", string:banner) )
 {
  security_warning(port);
  exit(0);
 }
}

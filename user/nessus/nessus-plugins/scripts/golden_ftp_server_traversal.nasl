#
# (C) Tenable Network Security
#


if (description) {
  script_id(18194);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1484");
  script_bugtraq_id(13479);

  name["english"] = "Golden FTP Server Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP server is affected by a directory traversal flaw. 

Description :

The version of Golden FTP Server installed on the remote host is prone
to a directory traversal attack.  Specifically, an attacker can read
files located outside a share with '\\..' sequences subject to the
privileges of the FTP server process. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-05/0033.html

Solution : 

Use an FTP proxy to filter malicious character sequences, place the
FTP root on a separate drive, or restrict access using NTFS. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:R/C:C/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for directory traversal vulnerability in Golden FTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
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
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
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
soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);
if (!soc2) exit(0);

# Identify some directories on the remote.
c = string("LIST /");
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[++ndirs] = substr(line, 55);
  }
  # 10 directories should be enough for testing.
  if (ndirs > 10) break;
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Iterate several times while trying to get the file's size.
  #
  # nb: this is a handy way to see if the file can be 
  #     retrieved without going through the hassle of 
  #     actually retrieving it.
  i = 0;
  file = "msdos.sys";
  while (++i < 5) {
    file = raw_string("..\\", file);
    c = string("SIZE /", dir, "/\\", file);
    send(socket:soc, data:string(c, "\r\n"));
    s = ftp_recv_line(socket:soc);

    # If we get a 213 followed by a size, there's a problem.
    if (egrep(string:s, pattern:"^213 [0-9]+")) {
      security_note(port);
      exit(0);
    }
  }
}


# Close the connections.
close(soc2);
ftp_close(socket:soc);

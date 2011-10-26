#
# (C) Tenable Network Security
#


if (description) {
  script_id(18587);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2085");
  script_bugtraq_id(14077);
 
  name["english"] = "Inframail FTP Server Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote FTP server is vulnerable to a buffer overflow attack. 

Description :

The remote host is running the FTP server component of Inframail, a
commercial suite of network servers from Infradig Systems. 

According to its banner, the installed version of Inframail suffers
from a buffer overflow vulnerability that arises when the FTP server
component processes an NLST command with an excessively long argument
(around 102400 bytes).  Successful exploitation will cause the service
to crash and may allow arbitrary code execution. 

See also : 

http://reedarvin.thearvins.com/20050627-01.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0348.html

Solution : 

Upgrade to Inframail 7.12 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerability in Inframail FTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp", "ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Do a banner check for the vulnerability.
banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(string:banner, pattern:"InfradigServers-FTP \(([0-5]\..*|6.([0-2].*|3[0-7]))\)")
) {
  security_warning(port);
}

#
# (C) Tenable Network Security
#


if (description) {
  script_id(19302);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2390");
  script_bugtraq_id(14380, 14381);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18270");
    script_xref(name:"OSVDB", value:"18271");
  }

  name["english"] = "ProFTPD < 1.3.0rc2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP server is affected by multiple vulnerabilities. 

Description :

The remote host is using ProFTPD, a free FTP server for Unix and
Linux. 

According to its banner, the version of ProFTPD installed on the
remote host suffers from multiple format string vulnerabilities, one
involving the 'ftpshut' utility and the other in mod_sql's
'SQLShowInfo' directive.  Exploitation of either requires involvement
on the part of a site administrator and can lead to information
disclosure, denial of service, and even a compromise of the affected
system. 

See also : 

http://www.proftpd.org/docs/RELEASE_NOTES-1.3.0rc2

Solution : 

Upgrade to ProFTPD version 1.3.0rc2 or later.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in ProFTPD < 1.3.0rc2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Check the version number in the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);
banner = get_ftp_banner(port:port);
if (
  banner &&  
  banner =~ "220[ -]ProFTPD (0\..+|1\.([0-2]\..+|3\.0rc1)) Server"
) security_note(port);

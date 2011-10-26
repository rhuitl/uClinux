#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21324);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2172");
  script_bugtraq_id(17810);
  script_xref(name:"OSVDB", value:"25238");
 
  script_name(english:"Gene6 FTP Server Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks for buffer overflow vulnerabilities in Gene6 FTP Server");
 
 desc = "
Synopsis :

The remote FTP server is affected by buffer overflow flaws. 

Description :

The remote host appears to be using Gene6 FTP Server, a professional
FTP server for Windows. 

According to its banner, the version of Gene6 FTP Server installed on
the remote host contains buffer overflow vulnerabilities that can be
exploited by an authenticated, possibly anonymous, user with
specially-crafted 'MKD', 'RMD', 'XMKD', and 'XRMD' commands to crash
the affected application or execute arbitrary code on the affected
host. 

See also :

http://www.securityfocus.com/archive/1/432839/30/0/threaded
http://www.g6ftpserver.com/forum/index.php?showtopic=2515

Solution : 

Upgrade to Gene6 FTP Server version 3.8.0 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


banner = get_ftp_banner(port:port);
if (
  banner &&
  egrep(pattern:"^220[- ]Gene6 FTP Server v([0-2]\.|3\.([0-6]\.*|7\.0))", string:banner)
) security_warning(port);

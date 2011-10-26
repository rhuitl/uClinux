#
# (C) Tenable Network Security
#


if (description)
{
 script_id(22048);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2006-5157", "CVE-2006-5211", "CVE-2006-5212");
 script_bugtraq_id(20284, 20330);

 script_name(english:"TrendMicro OfficeScan Multiple Vulnerabilities");
 script_summary(english:"Checks for OfficeScan stack overflows");
 
 desc = "
Synopsis :

The remote web server is vulnerable to remote code execution.

Description :

The remote host appears to be running Trend Micro OfficeScan Server.

This version of OfficeScan is vulnerable to multiple stack overflows in
CGI programs which may allow a remote attacker to execute code in
the context of the remote server.

Note that OfficeScan server under Windows runs with SYSTEM privileges,
which means an attacker can gain complete control of the affected host. 

In addition, there is a format string vulnerability in the
'ATXCONSOLE.OCX' ActiveX Control that may allow for remote code
execution via malicious input to the console's Remote Client Install
name search as well as flaws that might allow for removal of the
OfficeScan client or arbitrary files from the remote host. 

Solution :

TrendMicro has released 2 patches for OfficeScan 7.3:

http://esupport.trendmicro.com/support/viewxml.do?ContentID=EN-1031753
http://esupport.trendmicro.com/support/viewxml.do?ContentID=EN-1031702
http://www.layereddefense.com/TREND01OCT.html

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";

  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);

req = http_get (item:"/officescan/console/remoteinstallcgi/cgiRemoteInstall.exe", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if (!res || ( "Internal+error+when+cgiRemoteIninstall%2Eexe" >!< res))
  exit(0);

# the hotfix checks the length of each args (domain < 15)

req = http_get (item:"/officescan/console/remoteinstallcgi/cgiRemoteInstall.exe?domain=nessusnessusnessus&client=nessus&user=nessus&password=nessus&checkonly=true&filebase=test&action=1", port:port);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

send (socket:soc, data:req);
res = recv (socket:soc, length:4096, timeout:10);

if (res && ("Cannot+connect+to+nessus%2E" >< res))
  security_warning(port);

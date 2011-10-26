#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11755);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2001-0826", "CVE-2001-1335", "CVE-2001-1336", "CVE-2003-0329", "CVE-2004-0298", "CVE-2006-2961");
 script_bugtraq_id(2785, 2786, 2972, 7946, 7950, 9666, 18586);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8982");
   script_xref(name:"OSVDB", value:"9399");
   script_xref(name:"OSVDB", value:"26364");
 } 
 
 name["english"] = "CesarFTP multiple overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote FTP server is affected by multiple flaws.

Description :

The remote host is running CesarFTP, an FTP server for Windows systems. 

There are multiple flaws in this version of CesarFTP which may allow
an attcker to execute arbitrary code on this host, or simply to
disable this server remotely. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-05/0252.html
http://downloads.securityfocus.com/vulnerabilities/exploits/CesarFTP-ex1.pl
http://www.securiteam.com/exploits/5ZP0C0AIUA.html

Solution : 

Remove the software as it has not been updated since 2002.

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:N/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "CesarFTP overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(pattern:"^220 CesarFTP 0\.([0-8]|9[0-8]|99[a-g])", string:banner)
)
{
  security_warning(port);
  exit(0);
}


# Ferdy Riphagen pointed out that while the banne can be tweaked, the
# help command can not be.
if (thorough_tests)
{
  soc = open_sock_tcp(port);
  if (soc) {
    ftp_send_cmd(socket:soc, cmd:"HELP");
    res = recv(socket:soc, length:1024);
    ftp_close(socket:soc);

    if (
      res && 
      egrep(pattern:"CesarFTP server 0\.([0-8]|9[0-8]|99[a-g])", string:res)
    ) security_warning(port);
  }
}
exit(0);

#
# The following code freezes the GUI, but does not
# crash the FTP daemon
# 
send(socket:soc, data:'USER !@#$%^&*()_\r\n');
r = ftp_recv_line(socket:soc);
display(r);
send(socket:soc, data:'USER ' + crap(256) + '\r\n');
r = ftp_recv_line(socket:soc);
display(r);

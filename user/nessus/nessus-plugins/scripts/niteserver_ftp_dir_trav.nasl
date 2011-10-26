# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
#
# From: matrix@infowarfare.dk
# Subject: Directory traversal vulnerabilities found in NITE ftp-server version 1.83
# Date: Wed, 15 Jan 2003 13:10:46 +0100
#
# From: "Peter Winter-Smith" <peter4020@hotmail.com> 
# To: vulnwatch@vulnwatch.org, vuln@secunia.com, bugs@securitytracker.com
# Date: Wed, 06 Aug 2003 19:41:13 +0000
# Subject: Directory Traversal Vulnerability in 121 WAM! Server 1.0.4.0
#
# Vulnerable:
# NITE ftp-server version 1.83
# 121 WAM! Server 1.0.4.0
#

if(description)
{
 script_id(11466);
 script_bugtraq_id(6648);
 script_version ("$Revision: 1.10 $");
 
 desc["english"] = "
The remote FTP server allows anybody to switch to the 
root directory and read potentialy sensitive files.

Solution: Upgrade your FTP server
Risk factor: High";

 name["english"] = "NiteServer FTP directory traversal";
 
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to set the current directory to the root of the disk";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);


port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

if (! ftp_authenticate(socket:soc, user: "anonymous", pass: "nessus@example.com"))
{
  ftp_close(socket:soc);
  exit(0);
}
send(socket: soc, data: 'CWD\r\n');
r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (matches) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur1 = v[1];
      break;
    }
  }
}

# Loop on vulnerable patterns
dirs = make_list("\..\..\..\..\..", "/../");
foreach d (dirs)
{
send(socket: soc, data: 'CWD ' + d + '\r\n');

r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (matches) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur2 = v[1];
      break;
    }
  }
}

if (cur1 && cur2)
{
  if (cur1 != cur2)
    security_hole(port);
  ftp_close(socket: soc);
  exit(0);
}

p = ftp_pasv(socket:soc);
if(p)
{
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(soc2)
  {
     send(socket:soc, data: 'LIST\r\n');
     r = ftp_recv_listing(socket:soc2);
     r = tolower(r);
     r2 = ftp_recv_line(socket: soc);
     close(soc2);
     if ("autoexec.bat" >< r || "boot.ini" >< r || "config.sys" >< r)
     {
       security_hole(port);
       break;
     }
   }
}
}
ftp_close(socket: soc);

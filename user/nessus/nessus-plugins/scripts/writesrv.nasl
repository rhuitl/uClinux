#
# The script was written by Michel Arboi <arboi@alussinan.org>
# 
# It is released under the GNU Public Licence 
#

if(description)
{
  script_id(11222);
  script_version ("$Revision: 1.5 $");
#  script_cve_id("CVE-MAP-NOMATCH");
 
  name["english"] = "Writesrv";
  script_name(english:name["english"]);
 
  desc["english"] = "
writesrv is running on this port; it is used to send messages 
to users.
This service gives potential attackers information about who
is connected and who isn't, easing social engineering attacks for
example.

Solution: disable this service if you don't use it

Risk factor : Low";

  desc["francais"] = "
writesrv tourne sur ce port ; il sert à envoyer des messages 
aux utilisateurs.
Ce service donne aux attaquants potentiels des informations sur
qui est connecté et qui ne l'est pas, facilitant, par exemple, des
attaques par 'ingénierie sociale'.

Solution: désactivez ce service si vous ne l'utilisez pas.

Risk factor : Low";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detect writesrv";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2003 Michel Arboi");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 # script_dependencies("find_service.nes");
 exit(0);
}

# port = get_kb_item("Services/unknown");
port = 2401;	# Yes! Just like cvspserver!

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit (0);

m1 = "NESSUS" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
l0 = raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
m2 = "root" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

m = m1 + l0;
for (i=2; i < 32; i=i+1) m = m + l0;
m = m + m2;
for (i=2; i < 32; i=i+1) m = m + l0;

m = m + raw_string(0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, l0);
#display(m) ; exit(0);
send(socket: s, data: m);
r = recv(socket: s, length: 1536);
#display(r);

len = strlen(r);
if (len < 512) exit(0);	# Can 'magic read' break this?

# It seems that the answer is split into 512-bytes blocks padded 
# with nul bytes:
# <digit> <space> <digit> <enough bytes...>
# Then, if the user is logged:
# <ttyname> <nul bytes...>
# And maybe another block
# <tty2name> <nul bytes...>

for (i = 16; i < 512; i = i + 1)
{
  if (ord(r[i]) != 0) exit(0);
}

security_warning(port);

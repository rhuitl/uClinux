#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10380);
 script_version ("$Revision: 1.15 $");


 name["english"] = "rsh on finger output";
 name["francais"] = "rsh on finger output";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin attempts to log into the remote host
using rsh and uses the names given by the output
of finger.

Risk factor : High";


 desc["francais"] = "
Ce plugin essaye de se logguer sur la machine distante
en utilisant rsh et les noms donnés par la sortie
de la commande finger";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "attempts to log in using rsh";
 summary["francais"] = "essaye de se logguer en utilisant rsh";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "finger.nasl", "rsh.nasl");
 script_require_ports("Services/rsh", 514);
 script_require_keys("rsh/active");
 exit(0);
}


function login(port, name)
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = name + raw_string(0) + name + raw_string(0) + "id" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024);
  a = recv(socket:soc, length:1024);
  if(egrep(string:a, pattern:"^uid.*$"))
  {
   data = "It was possible to log into this host using the account '" + name +
   	  "' !" + string("\n") + "Either it is passwordless or the file " +
	  "~/.rhosts is not configured properly." + string("\n") + 
	  "Here is the output of the command 'id' : " + string("\n") + string("\n") + a + string("\n") +
	  "Solution : remove ~/.rhosts or set a password" + string("\n") +
	  "Risk factor : High";
   security_hole(port:port, data:data);
  }
  close(soc);
  }
}

port = get_kb_item("Services/rsh");
if(!port)port = 514;
if(!get_port_state(port))exit(0);

login(port:port, name:"root");

#
# these will most likely find backdoor rather
# than real unconfigured systems
#
login(port:port, name:"toor");
login(port:port, name:"bin");
login(port:port, name:"daemon");
login(port:port, name:"operator");
login(port:port, name:"nobody");
login(port:port, name:"adm");
login(port:port, name:"ftp");
login(port:port, name:"postgres");
login(port:port, name:"gdm");

finger_port = get_kb_item("Services/finger");
if(!finger_port)finger_port = 79;

if(!get_port_state(finger_port))exit(0);
finger = open_sock_tcp(finger_port);
if(!finger)exit(0);
send(socket:finger, data:string("\r\n"));
r = recv_line(socket:finger, length:1024);
if(!r)exit(0);
r = recv_line(socket:finger, length:1024);

tested = " root toor bin daemon operator nobody adm ftp postgres gdm ";

while(r)
{
  s = strstr(r," ");
  r = r - s;
  pat = ".* " + r + " .*";
  
  if(!egrep(string:tested, pattern:pat))
  {
  tested = tested + " " + r + " ";
  login(name:r, port:port);
  }
 r = recv_line(socket:finger, length:1024);
}

close(finger);

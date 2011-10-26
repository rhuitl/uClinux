#
# (C) Tenable Network Security
# 
#
#
# Ref: http://www.debian.org/security/2003/dsa-315

if(description)
{
 script_id(11736);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "gnocatan multiple buffer overflows";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running gnocatan, an online game server.

There is a flaw in this version which may allow an attacker to
execute arbitrary commands on this host, with the privileges
this service is running with.

An attacker may exploit this flaw to gain a shell on this host.

Solution : None at this time
Risk factor : High";
		 
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote Gnocatan Server can be overflown");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
 		  francais:"Ce script est Copyright (C) 2002 Tenable Network Security");
		  
 script_dependencies("find_service2.nasl");
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/gnocatan");
if(!port)port = 5556;
if ( ! get_port_state(port) ) exit(0);


soc = open_sock_tcp(port);
if(!soc)exit(0);
r = recv_line(socket:soc, length:4096);
if("version report" >< r)
{ 
 if(safe_checks())
 {
  report = "
The remote host is running gnocatan, an online game server.

There is a flaw in this version which may allow an attacker to
execute arbitrary commands on this host, with the privileges
this service is running with.

An attacker may exploit this flaw to gain a shell on this host.

*** As safe checks are enabled, Nessus did not check for this
*** vulnerability but solely relied on the presence of the service
*** to issue this alert 

Solution : None at this time
Risk factor : High";
		 
		 
  security_hole(port:port, data:report);
  exit(0);
 }

 send(socket:soc, data:'version ' + crap(4096) + '\n');
 r = recv_line(socket:soc, length:4096);
 if(strlen(r))exit(0);
 close(soc);
 
 soc = open_sock_tcp(port);
 if(!soc) { security_hole(port); exit(0); }
 r = recv_line(socket:soc, length:4096);
 if(!r) { security_hole(port); }
 close(soc);
}

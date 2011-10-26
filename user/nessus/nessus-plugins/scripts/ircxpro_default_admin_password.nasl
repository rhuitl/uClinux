#
# (C) Tenable Network Security
#
# 
#Ref: 
# From: "morning_wood" <se_cur_ity@hotmail.com>
# To: <bugtraq@securityfocus.com>
# Subject: IRCXpro 1.0 - Clear local and default remote admin passwords
# Date: Tue, 3 Jun 2003 00:57:45 -0700

if(description)
{
 script_id(11697);
 script_version ("$Revision: 1.2 $");
 
 
 name["english"] = "IRCXPro Default Admin password";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running IRCXPro.

It is possible to connect to the management port of this
service (by default : 7100) by using the default login/password
combination admin/password.

An attacker may use this flaw to gain the control of this server.

Solution : Disable this service or set a strong password and username
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote administrative interface of ircxpro";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/ircxpro_admin", 7100);
 script_dependencies("find_service.nes");
 exit(0);
}

port = get_kb_item("Services/ircxpro_admin");
if(!port)port = 7100;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
r = recv_line(socket:soc, length:4096);
if('IRCXPRO' >!< r) exit(0);
r = recv_line(socket:soc, length:4096);
send(socket:soc, data:'ISIRCXPRO\r\n');
r = recv_line(socket:soc, length:4096);
if('IRCXPRO' >!< r) exit(0);
send(socket:soc, data:'AUTH admin password\r\n');
r = recv_line(socket:soc, length:4096);
if("WELCOME" >< r) security_hole(port);

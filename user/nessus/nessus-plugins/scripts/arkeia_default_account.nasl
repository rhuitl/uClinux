#
# (C) Tenable Network Security
#
# Ref: http://metasploit.com/research/arkeia_agent/


if(description)
{
 script_id(17157);
 script_bugtraq_id(12600);
 script_version("$Revision: 1.1 $");

 name["english"] = "Knox Arkeia Network Backup Agent Unauthorized Access";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Arkea Network Backup agent, an agent system
designed to remotely perform backups of the remote host.

The remote version of this agent contains a default account 
which may allow an attacker to read arbitrary files on the remote system
with the privileges of the arkeia daemon (usually root);

Solution : Filter incoming traffic to this port
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the Arkeia Default account is present";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 script_require_ports(617);
 exit(0);
}


port = 617;
if  ( ! get_port_state(port) ) exit(0);

hello = raw_string(0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x00, 0x00, 0x7f, 0x41, 0x52, 0x4b, 0x41, 0x44, 0x4d, 0x49, 0x4e, 0x00, 0x72,
0x6f, 0x6f, 0x74, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x00, 0x34, 0x2e, 0x33, 0x2e, 0x30,
0x2d, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

soc = open_sock_tcp(port);
if ( ! soc ) exit( 0 );
send(socket:soc, data:hello);

r = recv(socket:soc, length:29);
if ( strlen(r) != 29 ) exit(0);

pkt = raw_string(0x00, 0x73, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x0c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);


send(socket:soc, data:pkt);

r = recv(socket:soc, length:32);
if ( strlen(r) != 32 ) exit(0);


pkt = raw_string ( 0, 0x61, 0, 4, 0, 1, 0, 0x15, 0, 0) + "15398" + raw_string(0) + "EN" + crap(data:raw_string(0), length:11);

send(socket:soc, data:pkt);

r = recv(socket:soc, length:8);
if ( strlen(r) != 8 ) exit(0);

pkt = raw_string(0, 0x62, 0x00, 0x01, 0x00, 0x02, 0x00) + "%ARKADMIN_GET_CLIENT_INFO" + raw_string(0) + "2" + crap(length:11, data:raw_string(0));
send(socket:soc, data:pkt);
r = recv(socket:soc, length:8);
if ( strlen(r) != 8 ) exit(0);

pkt  = raw_string(0x00, 0x63, 0x00, 0x04, 0x00, 0x03, 0x00, 0x11, 0x30, 0x00, 0x31, 0x00, 0x32) + crap(length:12, data:raw_string(0));
send(socket:soc, data:pkt);
r = recv(socket:soc, length:65535);
str = strstr(r, "Arkeia Network Backup ");
if ( ! str ) exit(0);
for ( i = 0; ord(str[i]) != 0 ; i ++)
{
 version += str[i];
}

version_num = ereg_replace(pattern:"Arkeia Network Backup ([0-9.]*)", replace:"\1", string:version);

set_kb_item(name:"arkeia-client/" + port, value:version_num);

report = "
The remote host is running Arkea Network Backup agent, an agent system
designed to remotely perform backups of the remote host.

The remote version of this agent contains a default account 
which may allow an attacker to read arbitrary files on the remote system
with the privileges of the arkeia daemon (usually root).


The remote version of this software is : " + version  + "

Solution : Filter incoming traffic to this port.
Risk factor : High";
 security_hole(port:port, data:report);




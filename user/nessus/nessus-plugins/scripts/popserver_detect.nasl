
#
# (C) Tenable Network Security
#
 desc["english"] = "
Synopsis :

A POP server is listening on the remote port

Description :

The remote host is running a POP server. 

Solution : 

Disable this service if you do not use it.

Risk factor : 

None";

if(description)
{
 script_id(10185);
 script_version ("$Revision: 1.17 $");
 name["english"] = "POP Server Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "POP Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/pop3", 110);
 
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

line = recv_line(socket:soc, length:4096);

if ( line =~ "+OK " )
{
 send(socket:soc, data:'LIST\r\n');
 r = recv_line(socket:soc, length:1024);
 if ( r =~ "+OK " ) exit(0); # Apop ?
 send(socket:soc, data:'USER ' + rand_str(length:8) + '\r\n');
 r = recv_line(socket:soc, length:1024);
 close(soc);
 if ( r !~ "^(\+OK|-ERR)" ) exit(0);
 report = desc["english"] + '\n\nPlugin output :\n\nRemote POP server banner :\n' + line;
 security_note(port:port, data:report);
}

#
# (C) Tenable Network Security
#
 desc["english"] = "
Synopsis :

An NNTP server is listening on the remote port

Description :

The remote host is running a news server (NNTP).  Make sure
that hosting such a server is authorized by your company 
policy.

Solution : 

Disable this service if you do not use it.


Risk factor : 

None";

if(description)
{
 script_id(10159);
 script_version ("$Revision: 1.17 $");
 name["english"] = "NNTP Server Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "NNTP Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/nntp");
if ( ! port ) port = 119;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = line = recv_line(socket:soc, length:4096);
while ( r[3] == "-" )
{
 r = recv_line(socket:soc, length:4096);
 line += r;
}


if ( line =~ "^200" )
	{
	send(socket:soc, data:'authinfo user ' + rand_str(length:8) + '\r\n');
	r = recv_line(socket:soc, length:255);
	if ( r =~ "^381" ) {
		report = desc["english"] + '\n\nPlugin output :\n\nRemote server banner :\n' + line;
		security_note(port:port, data:report);
		}
	}
close(soc);
exit(0);



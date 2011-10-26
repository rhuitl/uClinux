#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12259);
 script_version ("$Revision: 1.2 $");

 name["english"] = "Subversion Detection";
 script_name(english:name["english"]);

 desc["english"] =
"The remote host is running the Subversion server.  Subversion
is a software product which is similar to CVS in that it manages
file revisions and can be accessed across a network by multiple
clients.  Subversion typically listens on TCP port 3690.

See also : http://subversion.tigris.org
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Subversion Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports(3690);
 exit(0);
}



include("misc_func.inc");
# start check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);


soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

if ("success ( 1 2" >< r)
{
	security_note(port);
}

close(soc);
exit(0);

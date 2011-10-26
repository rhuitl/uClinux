#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12260);
 script_bugtraq_id(10428);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Subversion Pre-Commit-Hook Vulnerability";
 script_name(english:name["english"]);

 desc["english"] =
"The remote host is reported vulnerable to a remote 
overflow.  An attacker, exploiting this hole, would be
given full access to the target machine.  Versions of
Subversion less than 1.0.4 are vulnerable to this attack.

Solution : Upgrade to version 1.0.4 or higher
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Subversion Pre-Commit-Hook Vulnerability";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("subversion_detection.nasl");
 script_require_ports("Services/subversion");
 exit(0);
}



# start check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/nessusr0x ) ");

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);

if (! r)
	exit(0);

#display(r);

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-3][^0-9].*"))
{
	security_hole(port);
}

close(soc);
exit(0);

#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15773);
 script_version ("$Revision: 1.2 $");
 name["english"] = "CCProxy Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CCProxy, an application proxy supporting
many protocols (Telnet, FTP, WWW, and more...).

An open proxy may allow users to impersonate the remote host when
connecting to the outside. It might also allow spammer to use the remote
host as a relay.

Make sure the use of this program matches your corporate policy.

Solution : Disable this software if it violates your corporate policy
Risk Factor : Medium";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Detects CCProxy";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Firewalls"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ccproxy-telnet");
if ( port )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  r = recv_line(socket:soc, length:4096);
  if ( "CCProxy" >< r ) {
	security_warning ( port );
	exit(0);
	}
  close(soc);
 }
}
port = get_kb_item("Services/ccproxy-ftp");
if ( port )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  r = recv_line(socket:soc, length:4096);
  if ( "CCProxy" >< r ) {
	security_warning ( port );
	exit(0);
	}
  close(soc);
 }
}
port = get_kb_item("Services/ccproxy-smtp");
if ( port )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  r = recv_line(socket:soc, length:4096);
  if ( "CCProxy" >< r ) {
	security_warning ( port );
	exit(0);
	}
  close(soc);
 }
}

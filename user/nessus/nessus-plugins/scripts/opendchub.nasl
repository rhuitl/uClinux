#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15834);
 script_cve_id("CVE-2004-1127");
 script_bugtraq_id(11747);
 script_version("$Revision: 1.4 $");
 name["english"] = "Open DC Hub Remote Buffer Overflow Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of Open DC Hub, a peer-to-peer
file sharing application, which is vulnerable to a remote buffer
overflow. A successful exploit would allow a remote attacker to execute
code on the remote host.

It must be noted that the remote attacker needs administrative access to
this application.
 
Solution : None at this time.
Risk factor : Medium";



 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote system is running Open DC Hub";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes","find_service2.nasl");
 exit(0);
}

port = get_kb_item("Services/DirectConnectHub");
if ( port )
{
  sock = open_sock_tcp (port);
  if ( ! sock ) exit(0);

  data = recv (socket:sock, length:4000);
  if (egrep (pattern:"This hub is running version 0\.([0-6]\.[0-9]+|7\.([0-9][^0-9]|1[0-4])) of Open DC Hub", string:data))
  {
    security_warning(port);
    exit(0);
  }
}
else
{
  port = get_kb_item("Services/opendchub");
  if ( !port ) exit(0);

  sock = open_sock_tcp (port);
  if ( ! sock ) exit(0);

  data = recv (socket:sock, length:4000);
  if (egrep (pattern:"Open DC Hub, version 0\.([0-6]\.[0-9]+|7\.([0-9][^0-9]|1[0-4])), administrators port", string:data))
  {
    security_warning(port);
    exit(0);
  }
}

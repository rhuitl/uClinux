#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(21242);
  script_version("$Revision: 1.2 $");

  name["english"] = "Novell Messenger Messaging Agent Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host is running an instant messaging server.

Description :

The remote host is running Novell Messenger Messaging Agent,
an enterprise instant messaging server for Windows, Linux, and
Netware. 

Risk factor :

None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Novell Messenger Messaging Agent";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("httpver.nasl");
  script_require_ports("Services/www", 8300);

  exit(0);
}

include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port (default:8300);
if (!get_port_state(port)) exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

data = string ("GET /getdetails HTTP/1.0\r\n\r\n");

buf = http_keepalive_send_recv (data:data, port:port);

if ( buf &&
      ("HTTP/1.0 200" >< buf) &&
      ("NM_A_SZ_RESULT_CODE" >< buf) &&
      ("53505" >< buf) &&
      ("NM_A_SZ_TRANSACTION_ID" >< buf)
   )
{
 set_kb_item (name:string ("Novell/NMMA/", port), value:TRUE);
 security_note (port);
}

#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(21241);
  script_version("$Revision: 1.1 $");

  name["english"] = "Novell Messenger Archive Agent Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host is running an instant messaging server.

Description :

The remote host is running Novell Messenger Archive Agent,
an enterprise instant messaging server for Windows, Linux, and
Netware. 

Solution :

If you do not use this software, disable it.

Risk factor :

None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Novell Messenger Archive Agent";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("httpver.nasl");
  script_require_ports("Services/www", 8310);

  exit(0);
}

include("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:8310);
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

data = string ("GET /logout HTTP/1.0\r\n\r\n");

buf = http_keepalive_send_recv (data:data, port:port);

if ( buf &&
     ("HTTP/1.0 200" >< buf) &&
     ("NM_A_SZ_RESULT_CODE" >< buf) &&
     ("53505" >< buf) &&
     ("NM_A_SZ_TRANSACTION_ID" >< buf)
   )
  security_note (port);

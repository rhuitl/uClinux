#
# (C) Tenable Network Security
#


if (description) {
  script_id(21243);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0992");
  script_bugtraq_id (17503);
  script_xref(name:"OSVDB", value:"24617");

  name["english"] = "Novell GroupWise Messenger Accept Language Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

It is possible to execute code on the remote web server. 

Description :

The remote host is running Novell Messenger Messaging Agent, an
enterprise instant messaging server for Windows, Linux, and Netware. 

This version of this service is running an HTTP server which is
vulnerable to a stack overflow. 

An attacker can exploit this vulnerability to execute code on the
remote host. 

Solution :

Upgrade to Groupwise Messenger 2.0.1 beta3 or later.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Novell Messenger Messaging Agent Buffer overflow";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("nmma_detection.nasl");
  script_require_ports("Services/www", 8300);

  exit(0);
}

include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:8300);
kb = get_kb_item("Novel/NMMA/" + port);
if (!kb) exit(0);

if (!get_port_state(port))
  exit (0);

# getlocation command was not in 2.0.0
data = string ("GET /getlocation HTTP/1.0\r\n\r\n");

buf = http_keepalive_send_recv (port:port, data:data);

# patched version replies with the download page

if (egrep (pattern:"^HTTP/1.0 200", string:buf) && ("NM_A_SZ_RESULT_CODE" >!< buf))
  security_hole (port);

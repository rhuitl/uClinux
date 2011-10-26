#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
Synopsis :

The remote host is running an antivirus.

Description :

The remote host is running TrendMicro OfficeScan client,
an embedded HTTP server used by TrendMicro Antivirus 
softwares.

Risk factor :

None";

if (description) {
  script_id(20109);
  script_version("$Revision: 1.4 $");

  name["english"] = "OfficeScan Client Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for OfficeScan client";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("httpver.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_unknown_svc();
if (!port) exit(0);
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

req = string ("GET /?[CAVIT] Test HTTP/1.0\r\n\r\n");
send (socket:soc, data:req);
res = http_recv (socket:soc);

if (res == NULL) exit(0);

if (egrep(string:res, pattern:"^Server: OfficeScan Client"))
{
 security_note(port:port, data:desc);
 set_kb_item (name:"TrendMicro/OfficeScanClient", value:port);
}

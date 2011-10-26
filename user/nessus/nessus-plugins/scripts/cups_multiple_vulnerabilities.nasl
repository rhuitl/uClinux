#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(16141);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2004-1267","CVE-2004-1268","CVE-2004-1269","CVE-2004-1270", "CVE-2005-2874");
  script_bugtraq_id(11968, 12004, 12005, 12007, 12200, 14265);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"12439");
    script_xref(name:"OSVDB", value:"12453");
    script_xref(name:"OSVDB", value:"12454");
    script_xref(name:"FLSA", value:"FEDORA-2004-559");
    script_xref(name:"FLSA", value:"FEDORA-2004-560");
    script_xref(name:"GLSA", value:"GLSA-200412-25");
  }

  name["english"] = "CUPS < 1.1.23 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running a CUPS server whose version number is
between 1.0.4 and 1.1.22 inclusive.  Such versions are prone to
multiple vulnerabilities :

  - A remotely exploitable buffer overflow in the 'hpgltops'
    filter that enable specially crafted HPGL files can 
    execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing 
    his or her password until a temporary copy of the new 
    password file is cleaned up ('lppasswd' flaw).

  - A local user may be able to add arbitrary content to the 
    password file by closing the stderr file descriptor 
    while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS 
    password file, thereby denying service to valid clients 
   using digest authentication. (lppasswd flaw).

  - The application applys ACLs to incoming print jobs in a 
    case-sensitive fashion. Thus, an attacker can bypass 
    restrictions by changing the case in printer names when 
    submitting jobs. [Fixed in 1.1.21.]

***** Nessus has determined the vulnerability exists simply
***** by looking at the version number of CUPS installed on
***** the remote host.

See also : http://www.cups.org/str.php?L700
           http://www.cups.org/str.php?L1024
           http://www.cups.org/str.php?L1023
Solution : Upgrade to CUPS 1.1.23 or later.
Risk factor : High";
  script_description(english:desc["english"]);

  summary["english"] = "Checks version of CUPS";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  family["english"] = "Gain a shell remotely";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "http_version.nasl");
  script_require_keys("www/cups");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:631);
if (!port) exit(0);

# Check as long as it corresponds to a CUPS server.
banner = get_http_banner(port:port);
banner = strstr(banner, "Server: CUPS");
if (banner != NULL) {

  # Get the version number, if possible.
  banner = banner - strstr(banner, string("\n"));
  pat = "^Server: CUPS/?(.*)$";
  ver = eregmatch(string:banner, pattern:pat);
  if (isnull(ver)) exit(0);

  ver = chomp(ver[1]);
  if (ver =~ "^1\.(0(\.)?|1\.(1|2[0-2]))") 
    security_hole(port:port);
}

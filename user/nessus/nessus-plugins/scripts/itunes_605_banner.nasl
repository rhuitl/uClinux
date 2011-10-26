#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21783);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-1467");
  script_bugtraq_id(18730);

  script_name(english:"iTunes AAC File Integer Overflow Vulnerability (network check)");
  script_summary(english:"Check the version of iTunes"); 
 
 desc = "
Synopsis :

The remote host contains an application that is affected by a remote
code execution flaw. 

Description :

The remote host appears to be running iTunes, a popular jukebox program. 

The remote version of iTunes is vulnerable to an integer overflow when
it parses a specially crafted AAC file.  By tricking a user into
opening such a file, a remote attacker may be able to leverage this
issue to execute arbitrary code on the affected host, subject to the
privileges of the user running the application. 

See also :

http://www.securityfocus.com/advisories/10781
http://lists.apple.com/archives/security-announce//2006/Jun/msg00001.html

Solution :

Upgrade to iTunes 6.0.5 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("iTunes/" + port + "/enabled")) exit(0);


# Do a banner check (if music sharing is enabled and the app is running).
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^DAAP-Server: iTunes/([0-5]\.|6\.0\.[0-4][^0-9]?)", string:banner)
) security_warning(port);

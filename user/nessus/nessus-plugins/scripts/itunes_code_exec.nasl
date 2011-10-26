#
# (C) Tenable Network Security
#


if (description) {
  script_id(20218);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2938");
  script_bugtraq_id(15446);

  script_name(english:"iTunes For Windows Local Code Execution Vulnerability");
  script_summary(english:"Checks for an local code execution vulnerability in iTunes for Windows");
 
  desc = "
Synopsis :

The remote host contains an application that is affected by a local
code execution flaw. 

Description :

According to its banner, the version of iTunes for Windows on the
remote host launches a helper application by searching for it through
various system paths.  An attacker with local access can leverage this
issue to place a malicious program in a system path and have it called
before the helper application. 

See also :

http://www.idefense.com/application/poi/display?id=340&type=vulnerabilities
http://lists.apple.com/archives/security-announce/2005/Nov/msg00001.html

Solution :

Upgrade to iTunes 6 for Windows or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("itunes_sharing.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:3689);
if (!get_port_state(port)) exit(0);

if ( ! get_kb_item("iTunes/" + port + "/enabled") ) exit(0);


# Do a banner check (if music sharing is enabled).
banner = get_http_banner(port:port);
if (!banner) exit(0);
# nb: only Windows is affected.
if (egrep(pattern:"^DAAP-Server: iTunes/[0-5]\..+Windows", string:banner)) {
  security_warning(port);
}


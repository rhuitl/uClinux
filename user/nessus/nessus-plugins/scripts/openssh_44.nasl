#
# (C) Tenable Network Security
#


if (description) 
{
  script_id(22466);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-5051", "CVE-2006-5052");
  script_bugtraq_id(20241, 20245);

  name["english"] = "OpenSSH < 4.4 Multiple GSSAPI Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote SSH server is affected by multiple vulnerabilities. 

Description :

According to its banner, the version of OpenSSH installed on the
remote host contains a race condition that may allow an
unauthenticated remote attacker to crash the service or, on portable
OpenSSH, possibly execute code on the affected host.  In addition,
another flaw exists that may allow an attacker to determine the
validity of usernames on some platforms. 

Note that successful exploitation of these issues requires that GSSAPI
authentication be enabled. 

See also : 

http://www.openssh.com/txt/release-4.4

Solution : 

Upgrade to OpenSSH 4.4 or later.

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks version number of OpenSSH";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");


if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/ssh");
if (!port) port = 22;


auth = get_kb_item("SSH/supportedauth/" + port);
if (!auth) exit(0);
if ("gssapi" >!< auth) exit(0);


banner = get_kb_item("SSH/banner/" + port);
if (banner)
{
  banner = tolower(get_backport_banner(banner:banner));
  if (banner =~ "openssh[-_]([0-3]\.|4\.[0-3]([^0-9]|$))")
    security_warning(port);
}

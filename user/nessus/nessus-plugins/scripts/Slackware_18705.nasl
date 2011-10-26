# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='New sudo packages are available to fix a security problem which may allow
users to become root, or to execute arbitrary code as root.

Here\'s the information from the Slackware 8.0 ChangeLog:

----------------------------
Thu Apr 25 12:00:50 PDT 2002
patches/packages/sudo.tgz:  Upgraded to sudo-1.6.6.
  This version of sudo fixes a security problem whereby a local user may gain
  root access through corruption of the heap (Off-By-Five).
  This issue was discovered by Global InterSec LLC, and more information may
  be found on their web site:
  http://www.globalintersec.com/adv/sudo-2002041701.txt
  The discussion on the site indicates that this problem may only be exploitable
  on systems that use PAM, which Slackware does not use.  However, in the
  absence of proof, it still seems prudent to upgrade sudo immediately.
  (* Security fix *)
----------------------------

';
if (description) {
script_id(18705);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_summary("SSA sudo upgrade fixes a potential vulnerability");
name["english"] = "SSA- sudo upgrade fixes a potential vulnerability";
script_name(english:name["english"]);exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "sudo", pkgver: "1.6.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sudo is vulnerable in Slackware -current
Upgrade to sudo-1.6.6-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='New openssh packages are available to fix security problems.

Here\'s the information from the Slackware 8.0 ChangeLog:

----------------------------
Thu Mar  7 12:00:18 PST 2002
patches/packages/openssh.tgz:  Upgraded to openssh-3.1p1.

  This fixes a security problem in the openssh package.  All sites running
  OpenSSH should upgrade immediately.

  All versions of OpenSSH between 2.0 and 3.0.2 contain an off-by-one error
  in the channel code.  OpenSSH 3.1 and later are not affected.  This bug can
  be exploited locally by an authenticated user logging into a vulnerable
  OpenSSH server or by a malicious SSH server attacking a vulnerable OpenSSH
  client.  This bug was discovered by Joost Pol <joost@pine.nl>

(* Security fix *)
----------------------------

';
if (description) {
script_id(18700);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_summary("SSA OpenSSH security problem fixed");
name["english"] = "SSA- OpenSSH security problem fixed";
script_name(english:name["english"]);exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "openssh", pkgver: "3.1p1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware -current
Upgrade to openssh-3.1p1-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }

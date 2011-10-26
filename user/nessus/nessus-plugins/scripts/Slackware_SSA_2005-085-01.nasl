# This script was automatically generated from the SSA-2005-085-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Mozilla packages are available for Slackware 9.1, 10.0, 10.1, and -current
to fix various security issues and bugs.  See the Mozilla site for a complete
list of the issues patched:

  http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla

Also updated are Firefox and Thunderbird in Slackware -current, and GAIM in
Slackware 9.1, 10.0, and 10.1 (which uses the Mozilla NSS libraries).

New versions of the mozilla-plugins symlink creation package are also out for
Slackware 9.1, 10.0, and 10.1.

Just a little note on Slackware security -- I believe the state of Slackware
right now is quite secure.  I know there have been issues announced and fixed
elsewhere, and I am assessing the reality of them (to be honest, it seems the
level of proof needed to announce a security hole these days has fallen close
to zero -- where are the proof-of-concept exploits?)  It is, as always, my
firm intent to keep Slackware as secure as it can possibly be.  I\'m still
getting back up to speed (and I do not believe that anything exploitable in
real life is being allowed to slide), but I\'m continuing to look over the
various reports and would welcome input at security@slackware.com if you feel
anything important has been overlooked and is in need of attention.  Please
remember that I do read BugTraq and many other security lists.  I am not
asking for duplicates of BugTraq posts unless you have additional proof or
information on the issues, or can explain how an issue affects your own
servers.  This will help me to priorite any work that remains to be done.
Thanks in advance for any helpful comments.


';
if (description) {
script_id(18812);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-085-01");
script_summary("SSA-2005-085-01 Mozilla/Firefox/Thunderbird ");
name["english"] = "SSA-2005-085-01 Mozilla/Firefox/Thunderbird ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "gaim", pkgver: "1.2.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware 9.1
Upgrade to gaim-1.2.0-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mozilla", pkgver: "1.4.4", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware 9.1
Upgrade to mozilla-1.4.4-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mozilla-plugins", pkgver: "1.4.4", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-plugins is vulnerable in Slackware 9.1
Upgrade to mozilla-plugins-1.4.4-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "gaim", pkgver: "1.2.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware 10.0
Upgrade to gaim-1.2.0-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla", pkgver: "1.7.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware 10.0
Upgrade to mozilla-1.7.6-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla-plugins", pkgver: "1.7.6", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-plugins is vulnerable in Slackware 10.0
Upgrade to mozilla-plugins-1.7.6-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "gaim", pkgver: "1.2.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware 10.1
Upgrade to gaim-1.2.0-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla", pkgver: "1.7.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware 10.1
Upgrade to mozilla-1.7.6-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla-plugins", pkgver: "1.7.6", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-plugins is vulnerable in Slackware 10.1
Upgrade to mozilla-plugins-1.7.6-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gaim", pkgver: "1.2.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware -current
Upgrade to gaim-1.2.0-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "jre-symlink", pkgver: "1.0.2", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package jre-symlink is vulnerable in Slackware -current
Upgrade to jre-symlink-1.0.2-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla", pkgver: "1.7.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware -current
Upgrade to mozilla-1.7.6-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-firefox", pkgver: "1.0.2", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-firefox is vulnerable in Slackware -current
Upgrade to mozilla-firefox-1.0.2-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-thunderbird", pkgver: "1.0.2", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-thunderbird is vulnerable in Slackware -current
Upgrade to mozilla-thunderbird-1.0.2-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }

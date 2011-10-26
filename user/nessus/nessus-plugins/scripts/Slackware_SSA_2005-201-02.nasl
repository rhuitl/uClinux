# This script was automatically generated from the SSA-2005-201-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

New emacs packages are available for Slackware 10.1 and -current to
a security issue with the movemail utility for retrieving mail from
a POP mail server.  If used to connect to a malicious POP server, it
is possible for the server to cause the execution of arbitrary code as
the user running emacs.

';
if (description) {
script_id(19851);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-201-02");
script_summary("SSA-2005-201-02 emacs movemail POP utility ");
name["english"] = "SSA-2005-201-02 emacs movemail POP utility ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.1", pkgname: "emacs", pkgver: "21.4a", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs is vulnerable in Slackware 10.1
Upgrade to emacs-21.4a-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "emacs-info", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-info is vulnerable in Slackware 10.1
Upgrade to emacs-info-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "emacs-leim", pkgver: "21.4", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-leim is vulnerable in Slackware 10.1
Upgrade to emacs-leim-21.4-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "emacs-lisp", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-lisp is vulnerable in Slackware 10.1
Upgrade to emacs-lisp-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "emacs-misc", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-misc is vulnerable in Slackware 10.1
Upgrade to emacs-misc-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "emacs-nox", pkgver: "21.4a", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-nox is vulnerable in Slackware 10.1
Upgrade to emacs-nox-21.4a-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs", pkgver: "21.4a", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs is vulnerable in Slackware -current
Upgrade to emacs-21.4a-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs-info", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-info is vulnerable in Slackware -current
Upgrade to emacs-info-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs-leim", pkgver: "21.4", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-leim is vulnerable in Slackware -current
Upgrade to emacs-leim-21.4-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs-lisp", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-lisp is vulnerable in Slackware -current
Upgrade to emacs-lisp-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs-misc", pkgver: "21.4a", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-misc is vulnerable in Slackware -current
Upgrade to emacs-misc-21.4a-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "emacs-nox", pkgver: "21.4a", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package emacs-nox is vulnerable in Slackware -current
Upgrade to emacs-nox-21.4a-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }

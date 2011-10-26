# This script was automatically generated from the dsa-157
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The IRC client irssi is vulnerable to a denial of service condition.
The problem occurs when a user attempts to join a channel that has an
overly long topic description.  When a certain string is appended to
the topic, irssi will crash.
This problem has been fixed in version 0.8.4-3.1 for the current
stable distribution (woody) and in version 0.8.5-2 for the
unstable distribution (sid).  The old stable distribution (potato) is
not affected, since the corresponding portions of code are not
present.  The same applies to irssi-gnome and irssi-gtk, which don\'t
seem to be affected as well.
We recommend that you upgrade your irssi-text package.


Solution : http://www.debian.org/security/2002/dsa-157
Risk factor : High';

if (description) {
 script_id(14994);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "157");
 script_cve_id("CVE-2002-0983");
 script_bugtraq_id(5055);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA157] DSA-157-1 irssi-text");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-157-1 irssi-text");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'irssi-text', release: '3.0', reference: '0.8.4-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package irssi-text is vulnerable in Debian 3.0.\nUpgrade to irssi-text_0.8.4-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

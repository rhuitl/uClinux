# This script was automatically generated from the dsa-373
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Christian Jaeger discovered a buffer overflow in autorespond, an email
autoresponder used with qmail.  This vulnerability could potentially
be exploited by a remote attacker to gain the privileges of a user who
has configured qmail to forward messages to autorespond.  This
vulnerability is currently not believed to be exploitable due to
incidental limits on the length of the problematic input, but there
may be situations in which these limits do not apply.
For the stable distribution (woody) this problem has been fixed in
version 2.0.2-2woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your autorespond package.


Solution : http://www.debian.org/security/2003/dsa-373
Risk factor : High';

if (description) {
 script_id(15210);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "373");
 script_cve_id("CVE-2003-0654");
 script_bugtraq_id(8436);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA373] DSA-373-1 autorespond");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-373-1 autorespond");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'autorespond', release: '3.0', reference: '2.0.2-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package autorespond is vulnerable in Debian 3.0.\nUpgrade to autorespond_2.0.2-2woody1\n');
}
if (deb_check(prefix: 'autorespond', release: '3.0', reference: '2.0.2-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package autorespond is vulnerable in Debian woody.\nUpgrade to autorespond_2.0.2-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

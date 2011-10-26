# This script was automatically generated from the dsa-1015
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mark Dowd discovered a flaw in the handling of asynchronous signals in
sendmail, a powerful, efficient, and scalable mail transport agent.
This allows a remote attacker to exploit a race condition to
execute arbitrary code as root.
For the old stable distribution (woody) this problem has been fixed in
version 8.12.3-7.2.
For the stable distribution (sarge) this problem has been fixed in
version 8.13.4-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 8.13.6-1.
We recommend that you upgrade your sendmail package immediately.


Solution : http://www.debian.org/security/2006/dsa-1015
Risk factor : High';

if (description) {
 script_id(22557);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1015");
 script_cve_id("CVE-2006-0058");
 script_xref(name: "CERT", value: "834865");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1015] DSA-1015-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1015-1 sendmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendmail', release: '', reference: '8.13.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian .\nUpgrade to sendmail_8.13.6-1\n');
}
if (deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.0.\nUpgrade to libmilter-dev_8.12.3-7.2\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.0.\nUpgrade to sendmail_8.12.3-7.2\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.0.\nUpgrade to sendmail-doc_8.12.3-7.2\n');
}
if (deb_check(prefix: 'libmilter-dev', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter-dev is vulnerable in Debian 3.1.\nUpgrade to libmilter-dev_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'libmilter0', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmilter0 is vulnerable in Debian 3.1.\nUpgrade to libmilter0_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'rmail', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rmail is vulnerable in Debian 3.1.\nUpgrade to rmail_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian 3.1.\nUpgrade to sendmail_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail-base', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-base is vulnerable in Debian 3.1.\nUpgrade to sendmail-base_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail-bin', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-bin is vulnerable in Debian 3.1.\nUpgrade to sendmail-bin_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail-cf', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-cf is vulnerable in Debian 3.1.\nUpgrade to sendmail-cf_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail-doc', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail-doc is vulnerable in Debian 3.1.\nUpgrade to sendmail-doc_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sensible-mda', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sensible-mda is vulnerable in Debian 3.1.\nUpgrade to sensible-mda_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian sarge.\nUpgrade to sendmail_8.13.4-3sarge1\n');
}
if (deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendmail is vulnerable in Debian woody.\nUpgrade to sendmail_8.12.3-7.2\n');
}
if (w) { security_hole(port: 0, data: desc); }

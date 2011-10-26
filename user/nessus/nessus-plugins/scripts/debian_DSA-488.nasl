# This script was automatically generated from the dsa-488
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Christian Jaeger reported a bug in logcheck which could potentially be
exploited by a local user to overwrite files with root privileges.
logcheck utilized a temporary directory under /var/tmp without taking
security precautions.  While this directory is created when logcheck
is installed, and while it exists there is no vulnerability, if at
any time this directory is removed, the potential for exploitation exists.
For the current stable distribution (woody) this problem has been
fixed in version 1.1.1-13.1woody1.
For the unstable distribution (sid), this problem has been fixed in
version 1.1.1-13.2.
We recommend that you update your logcheck package.


Solution : http://www.debian.org/security/2004/dsa-488
Risk factor : High';

if (description) {
 script_id(15325);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "488");
 script_cve_id("CVE-2004-0404");
 script_bugtraq_id(10162);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA488] DSA-488-1 logcheck");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-488-1 logcheck");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'logcheck', release: '3.0', reference: '1.1.1-13.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package logcheck is vulnerable in Debian 3.0.\nUpgrade to logcheck_1.1.1-13.1woody1\n');
}
if (deb_check(prefix: 'logcheck-database', release: '3.0', reference: '1.1.1-13.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package logcheck-database is vulnerable in Debian 3.0.\nUpgrade to logcheck-database_1.1.1-13.1woody1\n');
}
if (deb_check(prefix: 'logtail', release: '3.0', reference: '1.1.1-13.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package logtail is vulnerable in Debian 3.0.\nUpgrade to logtail_1.1.1-13.1woody1\n');
}
if (deb_check(prefix: 'logcheck', release: '3.1', reference: '1.1.1-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package logcheck is vulnerable in Debian 3.1.\nUpgrade to logcheck_1.1.1-13.2\n');
}
if (deb_check(prefix: 'logcheck', release: '3.0', reference: '1.1.1-13.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package logcheck is vulnerable in Debian woody.\nUpgrade to logcheck_1.1.1-13.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

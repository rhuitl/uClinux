# This script was automatically generated from the dsa-814
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered that a script of lm-sensors,
utilities to read temperature/voltage/fan sensors, creates a temporary
file with a predictable filename, leaving it vulnerable for a symlink
attack.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.9.1-1sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.9.1-7.
We recommend that you upgrade your lm-sensors package.


Solution : http://www.debian.org/security/2005/dsa-814
Risk factor : High';

if (description) {
 script_id(19710);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "814");
 script_cve_id("CVE-2005-2672]");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA814] DSA-814-1 lm-sensors");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-814-1 lm-sensors");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lm-sensors', release: '', reference: '2.9.1-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors is vulnerable in Debian .\nUpgrade to lm-sensors_2.9.1-7\n');
}
if (deb_check(prefix: 'kernel-patch-2.4-lm-sensors', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4-lm-sensors is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4-lm-sensors_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'libsensors-dev', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsensors-dev is vulnerable in Debian 3.1.\nUpgrade to libsensors-dev_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'libsensors3', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsensors3 is vulnerable in Debian 3.1.\nUpgrade to libsensors3_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors is vulnerable in Debian 3.1.\nUpgrade to lm-sensors_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-386', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-386 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-386_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-586tsc', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-586tsc is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-586tsc_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-686', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-686 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-686_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-686-smp', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-686-smp_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-k6', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-k6 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-k6_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-k7', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-k7 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-k7_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-2-k7-smp', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-2-k7-smp_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors-source', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-source is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-source_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'sensord', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sensord is vulnerable in Debian 3.1.\nUpgrade to sensord_2.9.1-1sarge2\n');
}
if (deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors is vulnerable in Debian sarge.\nUpgrade to lm-sensors_2.9.1-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }

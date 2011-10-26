# This script was automatically generated from the dsa-122
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The compression library zlib has a flaw in which it attempts to free
memory more than once under certain conditions. This can possibly be
exploited to run arbitrary code in a program that includes zlib. If a
network application running as root is linked to zlib, this could
potentially lead to a remote root compromise. No exploits are known at
this time. This vulnerability is assigned the CVE candidate name of
CVE-2002-0059.
The zlib vulnerability is fixed in the Debian zlib package version
1.1.3-5.1. A number of programs either link statically to zlib or include
a private copy of zlib code. These programs must also be upgraded
to eliminate the zlib vulnerability. The affected packages and fixed
versions follow:
Those using the pre-release (testing) version of Debian should upgrade
to zlib 1.1.3-19.1 or a later version. Note that since this version of
Debian has not yet been released it may not be available immediately for
all architectures. Debian 2.2 (potato) is the latest supported release.
We recommend that you upgrade your packages immediately. Note that you
should restart all programs that use the shared zlib library in order
for the fix to take effect. This is most easily done by rebooting the
system.


Solution : http://www.debian.org/security/2002/dsa-122
Risk factor : High';

if (description) {
 script_id(14959);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "122");
 script_cve_id("CVE-2002-0059");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA122] DSA-122-1 zlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-122-1 zlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'amaya', release: '2.2', reference: '2.4-1potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package amaya is vulnerable in Debian 2.2.\nUpgrade to amaya_2.4-1potato1\n');
}
if (deb_check(prefix: 'dict', release: '2.2', reference: '1.4.9-9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dict is vulnerable in Debian 2.2.\nUpgrade to dict_1.4.9-9potato1\n');
}
if (deb_check(prefix: 'dictd', release: '2.2', reference: '1.4.9-9potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dictd is vulnerable in Debian 2.2.\nUpgrade to dictd_1.4.9-9potato1\n');
}
if (deb_check(prefix: 'erlang', release: '2.2', reference: '49.1-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package erlang is vulnerable in Debian 2.2.\nUpgrade to erlang_49.1-10.1\n');
}
if (deb_check(prefix: 'erlang-base', release: '2.2', reference: '49.1-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package erlang-base is vulnerable in Debian 2.2.\nUpgrade to erlang-base_49.1-10.1\n');
}
if (deb_check(prefix: 'erlang-erl', release: '2.2', reference: '49.1-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package erlang-erl is vulnerable in Debian 2.2.\nUpgrade to erlang-erl_49.1-10.1\n');
}
if (deb_check(prefix: 'erlang-java', release: '2.2', reference: '49.1-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package erlang-java is vulnerable in Debian 2.2.\nUpgrade to erlang-java_49.1-10.1\n');
}
if (deb_check(prefix: 'freeamp', release: '2.2', reference: '2.0.6-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp is vulnerable in Debian 2.2.\nUpgrade to freeamp_2.0.6-2.1\n');
}
if (deb_check(prefix: 'freeamp-doc', release: '2.2', reference: '2.0.6-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeamp-doc is vulnerable in Debian 2.2.\nUpgrade to freeamp-doc_2.0.6-2.1\n');
}
if (deb_check(prefix: 'libfreeamp-alsa', release: '2.2', reference: '2.0.6-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreeamp-alsa is vulnerable in Debian 2.2.\nUpgrade to libfreeamp-alsa_2.0.6-2.1\n');
}
if (deb_check(prefix: 'libfreeamp-esound', release: '2.2', reference: '2.0.6-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreeamp-esound is vulnerable in Debian 2.2.\nUpgrade to libfreeamp-esound_2.0.6-2.1\n');
}
if (deb_check(prefix: 'mirrordir', release: '2.2', reference: '0.10.48-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mirrordir is vulnerable in Debian 2.2.\nUpgrade to mirrordir_0.10.48-2.1\n');
}
if (deb_check(prefix: 'ppp', release: '2.2', reference: '2.3.11-1.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppp is vulnerable in Debian 2.2.\nUpgrade to ppp_2.3.11-1.5\n');
}
if (deb_check(prefix: 'rsync', release: '2.2', reference: '2.3.2-1.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rsync is vulnerable in Debian 2.2.\nUpgrade to rsync_2.3.2-1.6\n');
}
if (deb_check(prefix: 'vrweb', release: '2.2', reference: '1.5-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vrweb is vulnerable in Debian 2.2.\nUpgrade to vrweb_1.5-5.1\n');
}
if (deb_check(prefix: 'zlib-bin', release: '2.2', reference: '1.1.3-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib-bin is vulnerable in Debian 2.2.\nUpgrade to zlib-bin_1.1.3-5.1\n');
}
if (deb_check(prefix: 'zlib1', release: '2.2', reference: '1.1.3-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1 is vulnerable in Debian 2.2.\nUpgrade to zlib1_1.1.3-5.1\n');
}
if (deb_check(prefix: 'zlib1-altdev', release: '2.2', reference: '1.1.3-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1-altdev is vulnerable in Debian 2.2.\nUpgrade to zlib1-altdev_1.1.3-5.1\n');
}
if (deb_check(prefix: 'zlib1g', release: '2.2', reference: '1.1.3-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1g is vulnerable in Debian 2.2.\nUpgrade to zlib1g_1.1.3-5.1\n');
}
if (deb_check(prefix: 'zlib1g-dev', release: '2.2', reference: '1.1.3-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1g-dev is vulnerable in Debian 2.2.\nUpgrade to zlib1g-dev_1.1.3-5.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

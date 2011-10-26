# This script was automatically generated from the dsa-1193
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in the X Window System,
which may lead to the execution of arbitrary code or denial of service.
The Common Vulnerabilities and Exposures project identifies the
following problems:
    Chris Evan discovered an integer overflow in the code to handle
    PCF fonts, which might lead to denial of service if a malformed
    font is opened.
    It was discovered that an integer overflow in the code to handle
    Adobe Font Metrics might lead to the execution of arbitrary code.
    It was discovered that an integer overflow in the code to handle
    CMap and CIDFont font data might lead to the execution of arbitrary
    code.
    The XFree86 initialization code performs insufficient checking of
    the return value of setuid() when dropping privileges, which might
    lead to local privilege escalation.
For the stable distribution (sarge) these problems have been fixed in
version 4.3.0.dfsg.1-14sarge2. This release lacks builds for the
Motorola 680x0 architecture, which failed due to diskspace constraints
on the build host. They will be released once this problem has been
resolved.
For the unstable distribution (sid) these problems have been fixed
in version 1:1.2.2-1 of libxfont and version 1:1.0.2-9 of xorg-server.
We recommend that you upgrade your XFree86 packages.


Solution : http://www.debian.org/security/2006/dsa-1193
Risk factor : High';

if (description) {
 script_id(22734);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1193");
 script_cve_id("CVE-2006-3467", "CVE-2006-3739", "CVE-2006-3740", "CVE-2006-4447");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1193] DSA-1193-1 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1193-1 xfree86");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xfree86', release: '', reference: '1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86 is vulnerable in Debian .\nUpgrade to xfree86_1.2\n');
}
if (deb_check(prefix: 'lbxproxy', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lbxproxy is vulnerable in Debian 3.1.\nUpgrade to lbxproxy_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libdps-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps-dev is vulnerable in Debian 3.1.\nUpgrade to libdps-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libdps1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps1 is vulnerable in Debian 3.1.\nUpgrade to libdps1_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libdps1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps1-dbg is vulnerable in Debian 3.1.\nUpgrade to libdps1-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libice-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libice-dev is vulnerable in Debian 3.1.\nUpgrade to libice-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libice6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libice6 is vulnerable in Debian 3.1.\nUpgrade to libice6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libice6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libice6-dbg is vulnerable in Debian 3.1.\nUpgrade to libice6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libsm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsm-dev is vulnerable in Debian 3.1.\nUpgrade to libsm-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libsm6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsm6 is vulnerable in Debian 3.1.\nUpgrade to libsm6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libsm6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsm6-dbg is vulnerable in Debian 3.1.\nUpgrade to libsm6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libx11-6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libx11-6 is vulnerable in Debian 3.1.\nUpgrade to libx11-6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libx11-6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libx11-6-dbg is vulnerable in Debian 3.1.\nUpgrade to libx11-6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libx11-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libx11-dev is vulnerable in Debian 3.1.\nUpgrade to libx11-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6 is vulnerable in Debian 3.1.\nUpgrade to libxaw6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxaw6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw6-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6-dev is vulnerable in Debian 3.1.\nUpgrade to libxaw6-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw7', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7 is vulnerable in Debian 3.1.\nUpgrade to libxaw7_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw7-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7-dbg is vulnerable in Debian 3.1.\nUpgrade to libxaw7-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxaw7-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7-dev is vulnerable in Debian 3.1.\nUpgrade to libxaw7-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxext-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxext-dev is vulnerable in Debian 3.1.\nUpgrade to libxext-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxext6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxext6 is vulnerable in Debian 3.1.\nUpgrade to libxext6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxext6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxext6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxext6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxft1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxft1 is vulnerable in Debian 3.1.\nUpgrade to libxft1_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxft1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxft1-dbg is vulnerable in Debian 3.1.\nUpgrade to libxft1-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxi-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxi-dev is vulnerable in Debian 3.1.\nUpgrade to libxi-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxi6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxi6 is vulnerable in Debian 3.1.\nUpgrade to libxi6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxi6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxi6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxi6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmu-dev is vulnerable in Debian 3.1.\nUpgrade to libxmu-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmu6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmu6 is vulnerable in Debian 3.1.\nUpgrade to libxmu6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmu6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmu6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxmu6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmuu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmuu-dev is vulnerable in Debian 3.1.\nUpgrade to libxmuu-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmuu1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmuu1 is vulnerable in Debian 3.1.\nUpgrade to libxmuu1_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxmuu1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxmuu1-dbg is vulnerable in Debian 3.1.\nUpgrade to libxmuu1-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxp-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxp-dev is vulnerable in Debian 3.1.\nUpgrade to libxp-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxp6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxp6 is vulnerable in Debian 3.1.\nUpgrade to libxp6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxp6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxp6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxp6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxpm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxpm-dev is vulnerable in Debian 3.1.\nUpgrade to libxpm-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxpm4', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxpm4 is vulnerable in Debian 3.1.\nUpgrade to libxpm4_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxpm4-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxpm4-dbg is vulnerable in Debian 3.1.\nUpgrade to libxpm4-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxrandr-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxrandr-dev is vulnerable in Debian 3.1.\nUpgrade to libxrandr-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxrandr2', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxrandr2 is vulnerable in Debian 3.1.\nUpgrade to libxrandr2_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxrandr2-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxrandr2-dbg is vulnerable in Debian 3.1.\nUpgrade to libxrandr2-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxt-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxt-dev is vulnerable in Debian 3.1.\nUpgrade to libxt-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxt6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxt6 is vulnerable in Debian 3.1.\nUpgrade to libxt6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxt6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxt6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxt6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtrap-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtrap-dev is vulnerable in Debian 3.1.\nUpgrade to libxtrap-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtrap6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtrap6 is vulnerable in Debian 3.1.\nUpgrade to libxtrap6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtrap6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtrap6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxtrap6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtst-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtst-dev is vulnerable in Debian 3.1.\nUpgrade to libxtst-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtst6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtst6 is vulnerable in Debian 3.1.\nUpgrade to libxtst6_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxtst6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxtst6-dbg is vulnerable in Debian 3.1.\nUpgrade to libxtst6-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxv-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxv-dev is vulnerable in Debian 3.1.\nUpgrade to libxv-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxv1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxv1 is vulnerable in Debian 3.1.\nUpgrade to libxv1_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'libxv1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxv1-dbg is vulnerable in Debian 3.1.\nUpgrade to libxv1-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'pm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pm-dev is vulnerable in Debian 3.1.\nUpgrade to pm-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'proxymngr', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proxymngr is vulnerable in Debian 3.1.\nUpgrade to proxymngr_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'twm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package twm is vulnerable in Debian 3.1.\nUpgrade to twm_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'x-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-dev is vulnerable in Debian 3.1.\nUpgrade to x-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'x-window-system', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-window-system is vulnerable in Debian 3.1.\nUpgrade to x-window-system_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'x-window-system-core', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-window-system-core is vulnerable in Debian 3.1.\nUpgrade to x-window-system-core_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'x-window-system-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-window-system-dev is vulnerable in Debian 3.1.\nUpgrade to x-window-system-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xbase-clients', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbase-clients is vulnerable in Debian 3.1.\nUpgrade to xbase-clients_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xdm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xdm is vulnerable in Debian 3.1.\nUpgrade to xdm_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-100dpi', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-100dpi is vulnerable in Debian 3.1.\nUpgrade to xfonts-100dpi_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-100dpi-transcoded is vulnerable in Debian 3.1.\nUpgrade to xfonts-100dpi-transcoded_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-75dpi', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-75dpi is vulnerable in Debian 3.1.\nUpgrade to xfonts-75dpi_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-75dpi-transcoded is vulnerable in Debian 3.1.\nUpgrade to xfonts-75dpi-transcoded_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-base', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-base is vulnerable in Debian 3.1.\nUpgrade to xfonts-base_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-base-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-base-transcoded is vulnerable in Debian 3.1.\nUpgrade to xfonts-base-transcoded_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-cyrillic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-cyrillic is vulnerable in Debian 3.1.\nUpgrade to xfonts-cyrillic_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfonts-scalable', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-scalable is vulnerable in Debian 3.1.\nUpgrade to xfonts-scalable_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfree86-common', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86-common is vulnerable in Debian 3.1.\nUpgrade to xfree86-common_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfs is vulnerable in Debian 3.1.\nUpgrade to xfs_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfwp', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfwp is vulnerable in Debian 3.1.\nUpgrade to xfwp_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-dev is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-dri', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-dri is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-dri_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-dri-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-dri-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-dri-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-gl', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-gl is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-gl_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-gl-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-gl-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-gl-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-gl-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-gl-dev is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-gl-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-glu', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-glu is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-glu_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-glu-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-glu-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-glu-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa-glu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-glu-dev is vulnerable in Debian 3.1.\nUpgrade to xlibmesa-glu-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa3', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa3 is vulnerable in Debian 3.1.\nUpgrade to xlibmesa3_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibmesa3-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa3-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibmesa3-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibosmesa-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa-dev is vulnerable in Debian 3.1.\nUpgrade to xlibosmesa-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibosmesa4', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa4 is vulnerable in Debian 3.1.\nUpgrade to xlibosmesa4_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibosmesa4-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa4-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibosmesa4-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs is vulnerable in Debian 3.1.\nUpgrade to xlibs_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-data', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-data is vulnerable in Debian 3.1.\nUpgrade to xlibs-data_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-dbg is vulnerable in Debian 3.1.\nUpgrade to xlibs-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-dev is vulnerable in Debian 3.1.\nUpgrade to xlibs-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-pic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-pic is vulnerable in Debian 3.1.\nUpgrade to xlibs-pic_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-static-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-static-dev is vulnerable in Debian 3.1.\nUpgrade to xlibs-static-dev_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xlibs-static-pic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-static-pic is vulnerable in Debian 3.1.\nUpgrade to xlibs-static-pic_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xmh', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmh is vulnerable in Debian 3.1.\nUpgrade to xmh_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xnest', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xnest is vulnerable in Debian 3.1.\nUpgrade to xnest_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xserver-common', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xserver-common is vulnerable in Debian 3.1.\nUpgrade to xserver-common_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xserver-xfree86', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xserver-xfree86 is vulnerable in Debian 3.1.\nUpgrade to xserver-xfree86_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xserver-xfree86-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xserver-xfree86-dbg is vulnerable in Debian 3.1.\nUpgrade to xserver-xfree86-dbg_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xspecs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xspecs is vulnerable in Debian 3.1.\nUpgrade to xspecs_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xterm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xterm is vulnerable in Debian 3.1.\nUpgrade to xterm_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xutils', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xutils is vulnerable in Debian 3.1.\nUpgrade to xutils_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xvfb', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xvfb is vulnerable in Debian 3.1.\nUpgrade to xvfb_4.3.0.dfsg.1-14sarge2\n');
}
if (deb_check(prefix: 'xfree86', release: '3.1', reference: '4.3.0.dfsg.1-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86 is vulnerable in Debian sarge.\nUpgrade to xfree86_4.3.0.dfsg.1-14sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }

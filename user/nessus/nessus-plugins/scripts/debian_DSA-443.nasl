# This script was automatically generated from the dsa-443
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A number of vulnerabilities have been discovered in XFree86.  The corrections
are listed below with the identification from the Common
Vulnerabilities and Exposures (CVE) project:
    Buffer overflow in ReadFontAlias from dirfile.c of
    XFree86 4.1.0 through 4.3.0 allows local users and remote attackers to
    execute arbitrary code via a font alias file (font.alias) with a long
    token, a different vulnerability than CVE-2004-0084.
    Buffer overflow in the ReadFontAlias function in XFree86
    4.1.0 to 4.3.0, when using the CopyISOLatin1Lowered function, allows
    local or remote authenticated users to execute arbitrary code via a
    malformed entry in the font alias (font.alias) file, a different
    vulnerability than CVE-2004-0083.
    Miscellaneous additional flaws in XFree86\'s handling of
    font files.
    xdm does not verify whether the pam_setcred function call
    succeeds, which may allow attackers to gain root privileges by
    triggering error conditions within PAM modules, as demonstrated in
    certain configurations of the MIT pam_krb5 module.
    Denial-of-service attacks against the X
    server by clients using the GLX extension and Direct Rendering
    Infrastructure are possible due to unchecked client data (out-of-bounds
    array indexes [CVE-2004-0093] and integer signedness errors
    [CVE-2004-0094]).
Exploitation of CVE-2004-0083, CVE-2004-0084, CVE-2004-0106,
CVE-2004-0093 and CVE-2004-0094 would require a connection to the X
server.  By default, display managers in Debian start the X server
with a configuration which only accepts local connections, but if the
configuration is changed to allow remote connections, or X servers are
started by other means, then these bugs could be exploited remotely.
Since the X server usually runs with root privileges, these bugs could
potentially be exploited to gain root privileges.
No attack vector for CVE-2003-0690 is known at this time.
For the stable distribution (woody) these problems have been fixed in
version 4.1.0-16woody3.
For the unstable distribution (sid) these problems have been fixed in
version 4.3.0-2.
We recommend that you update your xfree86 package.


Solution : http://www.debian.org/security/2004/dsa-443
Risk factor : High';

if (description) {
 script_id(15280);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "443");
 script_cve_id("CVE-2003-0690", "CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0093", "CVE-2004-0106", "CVE-2004-0094");
 script_bugtraq_id(9636, 9652, 9655, 9701);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA443] DSA-443-1 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-443-1 xfree86");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lbxproxy', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lbxproxy is vulnerable in Debian 3.0.\nUpgrade to lbxproxy_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libdps-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps-dev is vulnerable in Debian 3.0.\nUpgrade to libdps-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libdps1', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps1 is vulnerable in Debian 3.0.\nUpgrade to libdps1_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libdps1-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdps1-dbg is vulnerable in Debian 3.0.\nUpgrade to libdps1-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw6', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6 is vulnerable in Debian 3.0.\nUpgrade to libxaw6_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw6-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6-dbg is vulnerable in Debian 3.0.\nUpgrade to libxaw6-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw6-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw6-dev is vulnerable in Debian 3.0.\nUpgrade to libxaw6-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw7', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7 is vulnerable in Debian 3.0.\nUpgrade to libxaw7_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw7-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7-dbg is vulnerable in Debian 3.0.\nUpgrade to libxaw7-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'libxaw7-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxaw7-dev is vulnerable in Debian 3.0.\nUpgrade to libxaw7-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'proxymngr', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proxymngr is vulnerable in Debian 3.0.\nUpgrade to proxymngr_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'twm', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package twm is vulnerable in Debian 3.0.\nUpgrade to twm_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'x-window-system', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-window-system is vulnerable in Debian 3.0.\nUpgrade to x-window-system_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'x-window-system-core', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package x-window-system-core is vulnerable in Debian 3.0.\nUpgrade to x-window-system-core_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xbase-clients', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbase-clients is vulnerable in Debian 3.0.\nUpgrade to xbase-clients_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xdm', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xdm is vulnerable in Debian 3.0.\nUpgrade to xdm_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-100dpi', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-100dpi is vulnerable in Debian 3.0.\nUpgrade to xfonts-100dpi_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-100dpi-transcoded is vulnerable in Debian 3.0.\nUpgrade to xfonts-100dpi-transcoded_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-75dpi', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-75dpi is vulnerable in Debian 3.0.\nUpgrade to xfonts-75dpi_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-75dpi-transcoded is vulnerable in Debian 3.0.\nUpgrade to xfonts-75dpi-transcoded_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-base', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-base is vulnerable in Debian 3.0.\nUpgrade to xfonts-base_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-base-transcoded', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-base-transcoded is vulnerable in Debian 3.0.\nUpgrade to xfonts-base-transcoded_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-cyrillic', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-cyrillic is vulnerable in Debian 3.0.\nUpgrade to xfonts-cyrillic_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-pex', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-pex is vulnerable in Debian 3.0.\nUpgrade to xfonts-pex_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfonts-scalable', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-scalable is vulnerable in Debian 3.0.\nUpgrade to xfonts-scalable_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfree86-common', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86-common is vulnerable in Debian 3.0.\nUpgrade to xfree86-common_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfs', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfs is vulnerable in Debian 3.0.\nUpgrade to xfs_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfwp', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfwp is vulnerable in Debian 3.0.\nUpgrade to xfwp_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlib6g', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlib6g is vulnerable in Debian 3.0.\nUpgrade to xlib6g_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlib6g-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlib6g-dev is vulnerable in Debian 3.0.\nUpgrade to xlib6g-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibmesa-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa-dev is vulnerable in Debian 3.0.\nUpgrade to xlibmesa-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibmesa3', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa3 is vulnerable in Debian 3.0.\nUpgrade to xlibmesa3_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibmesa3-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibmesa3-dbg is vulnerable in Debian 3.0.\nUpgrade to xlibmesa3-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibosmesa-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa-dev is vulnerable in Debian 3.0.\nUpgrade to xlibosmesa-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibosmesa3', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa3 is vulnerable in Debian 3.0.\nUpgrade to xlibosmesa3_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibosmesa3-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibosmesa3-dbg is vulnerable in Debian 3.0.\nUpgrade to xlibosmesa3-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibs', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs is vulnerable in Debian 3.0.\nUpgrade to xlibs_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibs-dbg', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-dbg is vulnerable in Debian 3.0.\nUpgrade to xlibs-dbg_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibs-dev', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-dev is vulnerable in Debian 3.0.\nUpgrade to xlibs-dev_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xlibs-pic', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xlibs-pic is vulnerable in Debian 3.0.\nUpgrade to xlibs-pic_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xmh', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmh is vulnerable in Debian 3.0.\nUpgrade to xmh_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xnest', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xnest is vulnerable in Debian 3.0.\nUpgrade to xnest_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xprt', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xprt is vulnerable in Debian 3.0.\nUpgrade to xprt_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xserver-common', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xserver-common is vulnerable in Debian 3.0.\nUpgrade to xserver-common_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xserver-xfree86', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xserver-xfree86 is vulnerable in Debian 3.0.\nUpgrade to xserver-xfree86_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xspecs', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xspecs is vulnerable in Debian 3.0.\nUpgrade to xspecs_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xterm', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xterm is vulnerable in Debian 3.0.\nUpgrade to xterm_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xutils', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xutils is vulnerable in Debian 3.0.\nUpgrade to xutils_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xvfb', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xvfb is vulnerable in Debian 3.0.\nUpgrade to xvfb_4.1.0-16woody3\n');
}
if (deb_check(prefix: 'xfree86', release: '3.1', reference: '4.3.0-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86 is vulnerable in Debian 3.1.\nUpgrade to xfree86_4.3.0-2\n');
}
if (deb_check(prefix: 'xfree86', release: '3.0', reference: '4.1.0-16woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfree86 is vulnerable in Debian woody.\nUpgrade to xfree86_4.1.0-16woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }

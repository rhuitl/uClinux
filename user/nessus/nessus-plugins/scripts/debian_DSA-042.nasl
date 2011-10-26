# This script was automatically generated from the dsa-042
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Klaus Frank has found a vulnerability in the way gnuserv
handled remote connections.  Gnuserv is a remote control facility for Emacsen
which is available as standalone program as well as included in XEmacs21.
Gnuserv has a buffer for which insufficient boundary checks were made.
Unfortunately this buffer affected access control to gnuserv which is using a
MIT-MAGIC-COOCKIE based system.  It is possible to overflow the buffer
containing the cookie and foozle cookie comparison.

Gnuserv was derived from emacsserver which is part of GNU Emacs.  It was
reworked completely and not much is left over from its time as part of
GNU Emacs.  Therefore the versions of emacsserver in both Emacs19 and Emacs20
doesn\'t look vulnerable to this bug, they don\'t even provide a MIT-MAGIC-COOKIE
based mechanism.

This could lead into a remote user issue commands under the UID of the
person running gnuserv.



Solution : http://www.debian.org/security/2001/dsa-042
Risk factor : High';

if (description) {
 script_id(14879);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "042");
 script_cve_id("CVE-2001-191");
 script_bugtraq_id(2333);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA042] DSA-042-1 gnuserv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-042-1 gnuserv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnuserv', release: '2.2', reference: '2.1alpha-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnuserv is vulnerable in Debian 2.2.\nUpgrade to gnuserv_2.1alpha-5.1\n');
}
if (deb_check(prefix: 'xemacs21', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21 is vulnerable in Debian 2.2.\nUpgrade to xemacs21_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-bin', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-bin is vulnerable in Debian 2.2.\nUpgrade to xemacs21-bin_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-mule', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-mule is vulnerable in Debian 2.2.\nUpgrade to xemacs21-mule_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-mule-canna-wnn', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-mule-canna-wnn is vulnerable in Debian 2.2.\nUpgrade to xemacs21-mule-canna-wnn_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-nomule', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-nomule is vulnerable in Debian 2.2.\nUpgrade to xemacs21-nomule_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-support', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-support is vulnerable in Debian 2.2.\nUpgrade to xemacs21-support_21.1.10-5\n');
}
if (deb_check(prefix: 'xemacs21-supportel', release: '2.2', reference: '21.1.10-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-supportel is vulnerable in Debian 2.2.\nUpgrade to xemacs21-supportel_21.1.10-5\n');
}
if (w) { security_hole(port: 0, data: desc); }

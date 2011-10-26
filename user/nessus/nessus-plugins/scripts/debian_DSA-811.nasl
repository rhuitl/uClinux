# This script was automatically generated from the dsa-811
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The bugfix for the problem mentioned below contained an error that
caused third party programs to fail.  The problem is corrected by this
update.  For completeness we\'re including the original advisory
text:
François-René Rideau discovered a bug in common-lisp-controller, a
Common Lisp source and compiler manager, that allows a local user to
compile malicious code into a cache directory which is executed by
another user if that user has not used Common Lisp before.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.15sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 4.18.
We recommend that you upgrade your common-lisp-controller package.


Solution : http://www.debian.org/security/2005/dsa-811
Risk factor : High';

if (description) {
 script_id(19690);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "811");
 script_cve_id("CVE-2005-2657");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA811] DSA-811-2 common-lisp-controller");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-811-2 common-lisp-controller");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'common-lisp-controller', release: '', reference: '4.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package common-lisp-controller is vulnerable in Debian .\nUpgrade to common-lisp-controller_4.18\n');
}
if (deb_check(prefix: 'common-lisp-controller', release: '3.1', reference: '4.15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package common-lisp-controller is vulnerable in Debian 3.1.\nUpgrade to common-lisp-controller_4.15sarge3\n');
}
if (deb_check(prefix: 'common-lisp-controller', release: '3.1', reference: '4.15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package common-lisp-controller is vulnerable in Debian sarge.\nUpgrade to common-lisp-controller_4.15sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }

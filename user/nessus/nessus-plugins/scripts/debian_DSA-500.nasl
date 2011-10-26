# This script was automatically generated from the dsa-500
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tatsuya Kinoshita discovered a vulnerability in flim, an emacs library
for working with internet messages, where temporary files were created
without taking appropriate precautions.  This vulnerability could
potentially be exploited by a local user to overwrite files with the
privileges of the user running emacs.
For the current stable distribution (woody) this problem has been
fixed in version 1.14.3-9woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your flim package.


Solution : http://www.debian.org/security/2004/dsa-500
Risk factor : High';

if (description) {
 script_id(15337);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "500");
 script_cve_id("CVE-2004-0422");
 script_bugtraq_id(10259);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA500] DSA-500-1 flim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-500-1 flim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'flim', release: '3.0', reference: '1.14.3-9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flim is vulnerable in Debian 3.0.\nUpgrade to flim_1.14.3-9woody1\n');
}
if (deb_check(prefix: 'flim', release: '3.0', reference: '1.14.3-9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package flim is vulnerable in Debian woody.\nUpgrade to flim_1.14.3-9woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

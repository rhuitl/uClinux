# This script was automatically generated from the dsa-264
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Upstream developers of lxr, a general hypertext cross-referencing
tool, have been alerted of a vulnerability that allows a remote
attacker to read arbitrary files on the host system as user www-data.
This could disclose local files that were not meant to be shared with
the public.
For the stable distribution (woody) this problem has been
fixed in version 0.3-3.
The old stable distribution (potato) is not affected since it does not
contain an lxr package.
For the unstable distribution (sid) this problem has been
fixed in version 0.3-4.
We recommend that you upgrade your lxr package.


Solution : http://www.debian.org/security/2003/dsa-264
Risk factor : High';

if (description) {
 script_id(15101);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "264");
 script_cve_id("CVE-2003-0156");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA264] DSA-264-1 lxr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-264-1 lxr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lxr', release: '3.0', reference: '0.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lxr is vulnerable in Debian 3.0.\nUpgrade to lxr_0.3-3\n');
}
if (deb_check(prefix: 'lxr', release: '3.1', reference: '0.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lxr is vulnerable in Debian 3.1.\nUpgrade to lxr_0.3-4\n');
}
if (deb_check(prefix: 'lxr', release: '3.0', reference: '0.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lxr is vulnerable in Debian woody.\nUpgrade to lxr_0.3-3\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-681
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund and Devin Carraway discovered that synaesthesia, a
program for representing sounds visually, accesses user-controlled
configuration and mixer files with elevated privileges.  Thus, it is
possible to read arbitrary files.
For the stable distribution (woody) this problem has been fixed in
version 2.1-2.1woody3.
For the testing (sarge) and unstable (sid) distribution this problem
does not exist since synaesthesia is not installed setuid root
anymore.
We recommend that you upgrade your synaesthesia package.


Solution : http://www.debian.org/security/2005/dsa-681
Risk factor : High';

if (description) {
 script_id(16457);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "681");
 script_cve_id("CVE-2005-0070");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA681] DSA-681-1 synaesthesia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-681-1 synaesthesia");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'synaesthesia', release: '3.0', reference: '2.1-2.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package synaesthesia is vulnerable in Debian 3.0.\nUpgrade to synaesthesia_2.1-2.1woody3\n');
}
if (deb_check(prefix: 'synaesthesia', release: '3.0', reference: '2.1-2.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package synaesthesia is vulnerable in Debian woody.\nUpgrade to synaesthesia_2.1-2.1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-563
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This advisory is an addition to DSA 563-1 and 563-2 which weren\'t able
to supersede the library on sparc and arm due to a different version
number for them in the stable archive. Other architectures were
updated properly. Another problem was reported in connection with
sendmail, though, which should be fixed with this update as well.
For the stable distribution (woody) this problem has been fixed in
version 1.5.27-3.1woody5.
For reference the advisory text follows:
A vulnerability has been discovered in the Cyrus implementation of the
SASL library, the Simple Authentication and Security Layer, a method
for adding authentication support to connection-based protocols.  The
library honors the environment variable SASL_PATH blindly, which
allows a local user to link against a malicious library to run
arbitrary code with the privileges of a setuid or setgid application.
For the unstable distribution (sid) this problem has been fixed in
version 1.5.28-6.2 of cyrus-sasl and in version 2.1.19-1.3 of
cyrus-sasl2.
We recommend that you upgrade your libsasl packages.


Solution : http://www.debian.org/security/2004/dsa-563
Risk factor : High';

if (description) {
 script_id(15661);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "563");
 script_cve_id("CVE-2004-0884");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA563] DSA-563-3 cyrus-sasl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-563-3 cyrus-sasl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libsasl-dev', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl-dev is vulnerable in Debian 3.0.\nUpgrade to libsasl-dev_1.5.27-3.1woody5\n');
}
if (deb_check(prefix: 'libsasl-digestmd5-plain', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl-digestmd5-plain is vulnerable in Debian 3.0.\nUpgrade to libsasl-digestmd5-plain_1.5.27-3.1woody5\n');
}
if (deb_check(prefix: 'libsasl-modules-plain', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl-modules-plain is vulnerable in Debian 3.0.\nUpgrade to libsasl-modules-plain_1.5.27-3.1woody5\n');
}
if (deb_check(prefix: 'libsasl7', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl7 is vulnerable in Debian 3.0.\nUpgrade to libsasl7_1.5.27-3.1woody5\n');
}
if (deb_check(prefix: 'sasl-bin', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sasl-bin is vulnerable in Debian 3.0.\nUpgrade to sasl-bin_1.5.27-3.1woody5\n');
}
if (deb_check(prefix: 'cyrus-sasl', release: '3.1', reference: '1.5.28-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-sasl is vulnerable in Debian 3.1.\nUpgrade to cyrus-sasl_1.5.28-6\n');
}
if (deb_check(prefix: 'cyrus-sasl', release: '3.0', reference: '1.5.27-3.1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-sasl is vulnerable in Debian woody.\nUpgrade to cyrus-sasl_1.5.27-3.1woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }

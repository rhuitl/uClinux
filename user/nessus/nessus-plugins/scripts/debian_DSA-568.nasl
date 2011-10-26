# This script was automatically generated from the dsa-568
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in the Cyrus implementation of the
SASL library, the Simple Authentication and Security Layer, a method
for adding authentication support to connection-based protocols.  The
library honors the environment variable SASL_PATH blindly, which
allows a local user to link against a malicious library to run
arbitrary code with the privileges of a setuid or setgid application.
The MIT version of the Cyrus implementation of the SASL library 
provides bindings against MIT GSSAPI and MIT Kerberos4.
For the stable distribution (woody) this problem has been fixed in
version 1.5.24-15woody3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your libsasl packages.


Solution : http://www.debian.org/security/2004/dsa-568
Risk factor : High';

if (description) {
 script_id(15666);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "568");
 script_cve_id("CVE-2004-0884");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA568] DSA-568-1 cyrus-sasl-mit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-568-1 cyrus-sasl-mit");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libsasl-gssapi-mit', release: '3.0', reference: '1.5.24-15woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl-gssapi-mit is vulnerable in Debian 3.0.\nUpgrade to libsasl-gssapi-mit_1.5.24-15woody3\n');
}
if (deb_check(prefix: 'libsasl-krb4-mit', release: '3.0', reference: '1.5.24-15woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl-krb4-mit is vulnerable in Debian 3.0.\nUpgrade to libsasl-krb4-mit_1.5.24-15woody3\n');
}
if (deb_check(prefix: 'cyrus-sasl-mit', release: '3.0', reference: '1.5.24-15woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-sasl-mit is vulnerable in Debian woody.\nUpgrade to cyrus-sasl-mit_1.5.24-15woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }

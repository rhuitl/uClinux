# This script was automatically generated from the dsa-228
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ilia Alshanetsky discovered several buffer overflows in libmcrypt, a
decryption and encryption library, that originates from improper or
lacking input validation.  By passing input which is longer than
expected to a number of functions (multiple functions are affected)
the user can successfully make libmcrypt crash and may be able to insert
arbitrary, malicious code which will be executed under the user
libmcrypt runs as, e.g. inside a web server.
Another vulnerability exists in the way libmcrypt loads algorithms via
libtool.  When different algorithms are loaded dynamically, each time
an algorithm is loaded a small part of memory is leaked.  In a
persistent environment (web server) this could lead to a memory
exhaustion attack that will exhaust all available memory by launching
repeated requests at an application utilizing the mcrypt library.
For the current stable distribution (woody) these problems have been
fixed in version 2.5.0-1woody1.
The old stable distribution (potato) does not contain libmcrypt packages.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.5-1.
We recommend that you upgrade your libmcrypt packages.


Solution : http://www.debian.org/security/2003/dsa-228
Risk factor : High';

if (description) {
 script_id(15065);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "228");
 script_cve_id("CVE-2003-0031", "CVE-2003-0032");
 script_bugtraq_id(6510, 6512);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA228] DSA-228-1 libmcrypt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-228-1 libmcrypt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmcrypt-dev', release: '3.0', reference: '2.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmcrypt-dev is vulnerable in Debian 3.0.\nUpgrade to libmcrypt-dev_2.5.0-1woody1\n');
}
if (deb_check(prefix: 'libmcrypt4', release: '3.0', reference: '2.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmcrypt4 is vulnerable in Debian 3.0.\nUpgrade to libmcrypt4_2.5.0-1woody1\n');
}
if (deb_check(prefix: 'libmcrypt', release: '3.1', reference: '2.5.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmcrypt is vulnerable in Debian 3.1.\nUpgrade to libmcrypt_2.5.5-1\n');
}
if (deb_check(prefix: 'libmcrypt', release: '3.0', reference: '2.5.0-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmcrypt is vulnerable in Debian woody.\nUpgrade to libmcrypt_2.5.0-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

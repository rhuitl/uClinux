# This script was automatically generated from the dsa-1189
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in OpenSSH, a free
implementation of the Secure Shell protocol, which may lead to denial of
service and potentially the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
    Tavis Ormandy of the Google Security Team discovered a denial of
    service vulnerability in the mitigation code against complexity
    attacks, which might lead to increased CPU consumption until a
    timeout is triggered. This is only exploitable if support for 
    SSH protocol version 1 is enabled.
    Mark Dowd discovered that insecure signal handler usage could
    potentially lead to execution of arbitrary code through a double
    free. The Debian Security Team doesn\'t believe the general openssh
    package without Kerberos support to be exploitable by this issue.
    However, due to the complexity of the underlying code we will
    issue an update to rule out all eventualities.
For the stable distribution (sarge) these problems have been fixed in
version 3.8.1p1-7sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 4.3p2-4 of openssh. openssh-krb5 will soon be converted towards
a transitional package against openssh.
We recommend that you upgrade your openssh-krb5 packages.


Solution : http://www.debian.org/security/2006/dsa-1189
Risk factor : High';

if (description) {
 script_id(22731);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1189");
 script_cve_id("CVE-2006-4924", "CVE-2006-5051");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1189] DSA-1189-1 openssh-krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1189-1 openssh-krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openssh-krb5', release: '', reference: '4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssh-krb5 is vulnerable in Debian .\nUpgrade to openssh-krb5_4\n');
}
if (deb_check(prefix: 'ssh-krb5', release: '3.1', reference: '3.8.1p1-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-krb5 is vulnerable in Debian 3.1.\nUpgrade to ssh-krb5_3.8.1p1-7sarge1\n');
}
if (deb_check(prefix: 'openssh-krb5', release: '3.1', reference: '3.8.1p1-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssh-krb5 is vulnerable in Debian sarge.\nUpgrade to openssh-krb5_3.8.1p1-7sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }

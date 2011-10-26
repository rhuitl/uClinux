# This script was automatically generated from the dsa-137
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner and Sebastian Krahmer discovered and fixed a temporary
file vulnerability in the mm shared memory library.  This problem can
be exploited to gain root access to a machine running Apache which is
linked against this library, if shell access to the user &ldquo;www-data&rdquo;
is already available (which could easily be triggered through PHP).
This problem has been fixed in the upstream version 1.2.0 of mm, which
will be uploaded to the unstable Debian distribution while this
advisory is released.  Fixed packages for potato (Debian 2.2) and
woody (Debian 3.0) are linked below.
We recommend that you upgrade your libmm packages immediately and
restart your Apache server.


Solution : http://www.debian.org/security/2002/dsa-137
Risk factor : High';

if (description) {
 script_id(14974);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "137");
 script_cve_id("CVE-2002-0658");
 script_bugtraq_id(5352);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA137] DSA-137-1 mm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-137-1 mm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmm10', release: '2.2', reference: '1.0.11-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmm10 is vulnerable in Debian 2.2.\nUpgrade to libmm10_1.0.11-1.2\n');
}
if (deb_check(prefix: 'libmm10-dev', release: '2.2', reference: '1.0.11-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmm10-dev is vulnerable in Debian 2.2.\nUpgrade to libmm10-dev_1.0.11-1.2\n');
}
if (deb_check(prefix: 'libmm11', release: '3.0', reference: '1.1.3-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmm11 is vulnerable in Debian 3.0.\nUpgrade to libmm11_1.1.3-6.1\n');
}
if (deb_check(prefix: 'libmm11-dev', release: '3.0', reference: '1.1.3-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmm11-dev is vulnerable in Debian 3.0.\nUpgrade to libmm11-dev_1.1.3-6.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

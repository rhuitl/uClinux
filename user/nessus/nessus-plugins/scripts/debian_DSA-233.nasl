# This script was automatically generated from the dsa-233
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered a problem in cvs, a concurrent versions
system, which is used for many Free Software projects.  The current
version contains a flaw that can be used by a remote attacker to
execute arbitrary code on the CVS server under the user id the CVS
server runs as.  Anonymous read-only access is sufficient to exploit
this problem.
For the stable distribution (woody) this problem has been
fixed in version 1.11.1p1debian-8.1.
For the old stable distribution (potato) this problem has been fixed
in version 1.10.7-9.2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your cvs package immediately.


Solution : http://www.debian.org/security/2003/dsa-233
Risk factor : High';

if (description) {
 script_id(15070);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "233");
 script_cve_id("CVE-2003-0015");
 script_xref(name: "CERT", value: "650937");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA233] DSA-233-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-233-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '2.2', reference: '1.10.7-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 2.2.\nUpgrade to cvs_1.10.7-9.2\n');
}
if (deb_check(prefix: 'cvs-doc', release: '2.2', reference: '1.10.7-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs-doc is vulnerable in Debian 2.2.\nUpgrade to cvs-doc_1.10.7-9.2\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.0.\nUpgrade to cvs_1.11.1p1debian-8.1\n');
}
if (deb_check(prefix: 'cvs', release: '2.2', reference: '1.10.7-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian potato.\nUpgrade to cvs_1.10.7-9.2\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.11.1p1debian-8.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

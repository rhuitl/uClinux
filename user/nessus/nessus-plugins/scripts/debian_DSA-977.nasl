# This script was automatically generated from the dsa-977
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in heimdal, a free
implementation of Kerberos 5.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
    Privilege escalation in the rsh server allows an authenticated
    attacker to overwrite arbitrary files and gain ownership of them.
    A remote attacker could force the telnet server to crash before
    the user logged in, resulting in inetd turning telnetd off because
    it forked too fast.
The old stable distribution (woody) does not expose rsh and telnet servers.
For the stable distribution (sarge) these problems have been fixed in
version 0.6.3-10sarge2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your heimdal packages.


Solution : http://www.debian.org/security/2006/dsa-977
Risk factor : High';

if (description) {
 script_id(22843);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "977");
 script_cve_id("CVE-2006-0582", "CVE-2006-0677");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA977] DSA-977-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-977-1 heimdal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heimdal-clients', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 3.1.\nUpgrade to heimdal-clients_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 3.1.\nUpgrade to heimdal-clients-x_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 3.1.\nUpgrade to heimdal-dev_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 3.1.\nUpgrade to heimdal-docs_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 3.1.\nUpgrade to heimdal-kdc_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 3.1.\nUpgrade to heimdal-servers_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 3.1.\nUpgrade to heimdal-servers-x_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libasn1-6-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libasn1-6-heimdal is vulnerable in Debian 3.1.\nUpgrade to libasn1-6-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libgssapi1-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgssapi1-heimdal is vulnerable in Debian 3.1.\nUpgrade to libgssapi1-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libhdb7-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libhdb7-heimdal is vulnerable in Debian 3.1.\nUpgrade to libhdb7-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5clnt4-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkadm5clnt4-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5srv7-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkadm5srv7-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libkafs0-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkafs0-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkafs0-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'libkrb5-17-heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-17-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkrb5-17-heimdal_0.6.3-10sarge2\n');
}
if (deb_check(prefix: 'heimdal', release: '3.1', reference: '0.6.3-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian sarge.\nUpgrade to heimdal_0.6.3-10sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }

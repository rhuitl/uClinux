# This script was automatically generated from the dsa-758
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in the telnet server from
Heimdal, a free implementation of Kerberos 5, that could lead to the
execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.4e-7.woody.10.
For the stable distribution (sarge) this problem has been fixed in
version 0.6.3-10sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.6.3-11.
We recommend that you upgrade your heimdal packages.


Solution : http://www.debian.org/security/2005/dsa-758
Risk factor : High';

if (description) {
 script_id(19220);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "758");
 script_cve_id("CVE-2005-2040");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA758] DSA-758-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-758-1 heimdal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heimdal', release: '', reference: '0.6.3-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian .\nUpgrade to heimdal_0.6.3-11\n');
}
if (deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients-x_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 3.0.\nUpgrade to heimdal-dev_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 3.0.\nUpgrade to heimdal-docs_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 3.0.\nUpgrade to heimdal-kdc_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-lib is vulnerable in Debian 3.0.\nUpgrade to heimdal-lib_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers-x_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libasn1-5-heimdal is vulnerable in Debian 3.0.\nUpgrade to libasn1-5-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcomerr1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libcomerr1-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgssapi1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libgssapi1-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libhdb7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libhdb7-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5clnt4-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5clnt4-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5srv7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5srv7-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkafs0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkafs0-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-17-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkrb5-17-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libotp0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libotp0-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libroken9-heimdal is vulnerable in Debian 3.0.\nUpgrade to libroken9-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsl0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libsl0-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libss0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libss0-heimdal_0.4e-7.woody.10\n');
}
if (deb_check(prefix: 'heimdal-clients', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 3.1.\nUpgrade to heimdal-clients_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 3.1.\nUpgrade to heimdal-clients-x_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 3.1.\nUpgrade to heimdal-dev_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 3.1.\nUpgrade to heimdal-docs_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 3.1.\nUpgrade to heimdal-kdc_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 3.1.\nUpgrade to heimdal-servers_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 3.1.\nUpgrade to heimdal-servers-x_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libasn1-6-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libasn1-6-heimdal is vulnerable in Debian 3.1.\nUpgrade to libasn1-6-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libgssapi1-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgssapi1-heimdal is vulnerable in Debian 3.1.\nUpgrade to libgssapi1-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libhdb7-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libhdb7-heimdal is vulnerable in Debian 3.1.\nUpgrade to libhdb7-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5clnt4-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkadm5clnt4-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5srv7-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkadm5srv7-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libkafs0-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkafs0-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkafs0-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'libkrb5-17-heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-17-heimdal is vulnerable in Debian 3.1.\nUpgrade to libkrb5-17-heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal', release: '3.1', reference: '0.6.3-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian sarge.\nUpgrade to heimdal_0.6.3-10sarge1\n');
}
if (deb_check(prefix: 'heimdal', release: '3.0', reference: '0.4e-7.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian woody.\nUpgrade to heimdal_0.4e-7.woody.10\n');
}
if (w) { security_hole(port: 0, data: desc); }

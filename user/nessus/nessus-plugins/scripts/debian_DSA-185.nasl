# This script was automatically generated from the dsa-185
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A stack buffer overflow in the kadm_ser_wrap_in function in the
Kerberos v4 administration server was discovered, which is provided by
Heimdal as well.  A working exploit for this kadmind bug is already
circulating, hence it is considered serious.  The broken library also
contains a vulnerability which could lead to another root exploit.
These problems have been fixed in version 0.4e-7.woody.5 for the
current stable distribution (woody), in version 0.2l-7.6 for the old
stable distribution (potato) and in version 0.4e-22 for the unstable
distribution (sid).
We recommend that you upgrade your heimdal packages immediately.


Solution : http://www.debian.org/security/2002/dsa-185
Risk factor : High';

if (description) {
 script_id(15022);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0016");
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "185");
 script_cve_id("CVE-2002-1235");
 script_xref(name: "CERT", value: "875073");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA185] DSA-185-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-185-1 heimdal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heimdal-clients', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 2.2.\nUpgrade to heimdal-clients_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 2.2.\nUpgrade to heimdal-clients-x_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 2.2.\nUpgrade to heimdal-dev_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 2.2.\nUpgrade to heimdal-docs_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 2.2.\nUpgrade to heimdal-kdc_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-lib', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-lib is vulnerable in Debian 2.2.\nUpgrade to heimdal-lib_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 2.2.\nUpgrade to heimdal-servers_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '2.2', reference: '0.2l-7.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 2.2.\nUpgrade to heimdal-servers-x_0.2l-7.6\n');
}
if (deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients-x_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 3.0.\nUpgrade to heimdal-dev_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 3.0.\nUpgrade to heimdal-docs_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 3.0.\nUpgrade to heimdal-kdc_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-lib is vulnerable in Debian 3.0.\nUpgrade to heimdal-lib_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers-x_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libasn1-5-heimdal is vulnerable in Debian 3.0.\nUpgrade to libasn1-5-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcomerr1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libcomerr1-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgssapi1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libgssapi1-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libhdb7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libhdb7-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5clnt4-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5clnt4-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5srv7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5srv7-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkafs0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkafs0-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-17-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkrb5-17-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libotp0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libotp0-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libroken9-heimdal is vulnerable in Debian 3.0.\nUpgrade to libroken9-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsl0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libsl0-heimdal_0.4e-7.woody.5\n');
}
if (deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libss0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libss0-heimdal_0.4e-7.woody.5\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-269
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cryptographic weakness in version 4 of the Kerberos protocol allows
an attacker to use a chosen-plaintext attack to impersonate any
principal in a realm.  Additional cryptographic weaknesses in the krb4
implementation permit the use of cut-and-paste attacks to fabricate
krb4 tickets for unauthorized client principals if triple-DES keys are
used to key krb4 services.  These attacks can subvert a site\'s entire
Kerberos authentication infrastructure.
This version of the heimdal package changes the default behavior and
disallows cross-realm authentication for Kerberos version 4.  Because
of the fundamental nature of the problem, cross-realm authentication
in Kerberos version 4 cannot be made secure and sites should avoid its
use.  A new option (--kerberos4-cross-realm) is provided to the kdc 
command to re-enable version 4 cross-realm authentication for those
sites that must use this functionality but desire the other security
fixes.
For the stable distribution (woody) this problem has been
fixed in version 0.4e-7.woody.8.
The old stable distribution (potato) is not affected by this problem,
since it isn\'t compiled against kerberos 4.
For the unstable distribution (sid) this problem has been
fixed in version 0.5.2-1.
We recommend that you upgrade your heimdal packages immediately.


Solution : http://www.debian.org/security/2003/dsa-269
Risk factor : High';

if (description) {
 script_id(15106);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "269");
 script_cve_id("CVE-2003-0138");
 script_xref(name: "CERT", value: "623217");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA269] DSA-269-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-269-1 heimdal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-clients-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-clients-x_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-dev is vulnerable in Debian 3.0.\nUpgrade to heimdal-dev_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-docs is vulnerable in Debian 3.0.\nUpgrade to heimdal-docs_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-kdc is vulnerable in Debian 3.0.\nUpgrade to heimdal-kdc_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-lib is vulnerable in Debian 3.0.\nUpgrade to heimdal-lib_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal-servers-x is vulnerable in Debian 3.0.\nUpgrade to heimdal-servers-x_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libasn1-5-heimdal is vulnerable in Debian 3.0.\nUpgrade to libasn1-5-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcomerr1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libcomerr1-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgssapi1-heimdal is vulnerable in Debian 3.0.\nUpgrade to libgssapi1-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libhdb7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libhdb7-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5clnt4-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5clnt4-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm5srv7-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkadm5srv7-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkafs0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkafs0-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-17-heimdal is vulnerable in Debian 3.0.\nUpgrade to libkrb5-17-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libotp0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libotp0-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libroken9-heimdal is vulnerable in Debian 3.0.\nUpgrade to libroken9-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsl0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libsl0-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libss0-heimdal is vulnerable in Debian 3.0.\nUpgrade to libss0-heimdal_0.4e-7.woody.8\n');
}
if (deb_check(prefix: 'heimdal', release: '3.1', reference: '0.5.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian 3.1.\nUpgrade to heimdal_0.5.2-1\n');
}
if (deb_check(prefix: 'heimdal', release: '3.0', reference: '0.4e-7.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heimdal is vulnerable in Debian woody.\nUpgrade to heimdal_0.4e-7.woody.8\n');
}
if (w) { security_hole(port: 0, data: desc); }

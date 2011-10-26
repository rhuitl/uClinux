# This script was automatically generated from the dsa-366
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
eroaster, a frontend for burning CD-R media using cdrecord, does not
take appropriate security precautions when creating a temporary file
for use as a lockfile.  This bug could potentially be exploited to
overwrite arbitrary files with the privileges of the user running
eroaster.
For the stable distribution (woody) this problem has been fixed in
version 2.1.0.0.3-2woody1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.0-0.5-1.
We recommend that you update your eroaster package.


Solution : http://www.debian.org/security/2003/dsa-366
Risk factor : High';

if (description) {
 script_id(15203);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "366");
 script_cve_id("CVE-2003-0656");
 script_bugtraq_id(8350);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA366] DSA-366-1 eroaster");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-366-1 eroaster");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'eroaster', release: '3.0', reference: '2.1.0.0.3-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eroaster is vulnerable in Debian 3.0.\nUpgrade to eroaster_2.1.0.0.3-2woody1\n');
}
if (deb_check(prefix: 'eroaster', release: '3.1', reference: '2.2.0-0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eroaster is vulnerable in Debian 3.1.\nUpgrade to eroaster_2.2.0-0.5-1\n');
}
if (deb_check(prefix: 'eroaster', release: '3.0', reference: '2.1.0.0.3-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eroaster is vulnerable in Debian woody.\nUpgrade to eroaster_2.1.0.0.3-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

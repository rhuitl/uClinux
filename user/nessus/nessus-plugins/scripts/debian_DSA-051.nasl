# This script was automatically generated from the dsa-051
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Florian Wesch has discovered a problem (reported to bugtraq) with the
way how Netscape handles comments in GIF files.  The Netscape browser
does not escape the GIF file comment in the image information page.
This allows javascript execution in the "about:" protocol and can for
example be used to upload the History (about:global) to a webserver,
thus leaking private information.  This problem has been fixed
upstream in Netscape 4.77.

Since we haven\'t received source code for these packages, they are not
part of the Debian GNU/Linux distribution, but are packaged up as `.deb\'
files for a convenient installation.

We recommend that you upgrade your Netscape packages immediately and
remove older versions.



Solution : http://www.debian.org/security/2001/dsa-051
Risk factor : High';

if (description) {
 script_id(14888);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "051");
 script_cve_id("CVE-2001-0596");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA051] DSA-051-1 netscape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-051-1 netscape");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'communicator', release: '2.2', reference: '4.77-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package communicator is vulnerable in Debian 2.2.\nUpgrade to communicator_4.77-1\n');
}
if (deb_check(prefix: 'communicator-base-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package communicator-base-477 is vulnerable in Debian 2.2.\nUpgrade to communicator-base-477_4.77-2\n');
}
if (deb_check(prefix: 'communicator-nethelp-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package communicator-nethelp-477 is vulnerable in Debian 2.2.\nUpgrade to communicator-nethelp-477_4.77-2\n');
}
if (deb_check(prefix: 'communicator-smotif-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package communicator-smotif-477 is vulnerable in Debian 2.2.\nUpgrade to communicator-smotif-477_4.77-2\n');
}
if (deb_check(prefix: 'communicator-spellchk-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package communicator-spellchk-477 is vulnerable in Debian 2.2.\nUpgrade to communicator-spellchk-477_4.77-2\n');
}
if (deb_check(prefix: 'navigator', release: '2.2', reference: '4.77-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package navigator is vulnerable in Debian 2.2.\nUpgrade to navigator_4.77-1\n');
}
if (deb_check(prefix: 'navigator-base-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package navigator-base-477 is vulnerable in Debian 2.2.\nUpgrade to navigator-base-477_4.77-2\n');
}
if (deb_check(prefix: 'navigator-nethelp-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package navigator-nethelp-477 is vulnerable in Debian 2.2.\nUpgrade to navigator-nethelp-477_4.77-2\n');
}
if (deb_check(prefix: 'navigator-smotif-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package navigator-smotif-477 is vulnerable in Debian 2.2.\nUpgrade to navigator-smotif-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape', release: '2.2', reference: '4.77-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape is vulnerable in Debian 2.2.\nUpgrade to netscape_4.77-1\n');
}
if (deb_check(prefix: 'netscape-base-4', release: '2.2', reference: '4.77-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-base-4 is vulnerable in Debian 2.2.\nUpgrade to netscape-base-4_4.77-1\n');
}
if (deb_check(prefix: 'netscape-base-4-libc5', release: '2.2', reference: '4.77-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-base-4-libc5 is vulnerable in Debian 2.2.\nUpgrade to netscape-base-4-libc5_4.77-1\n');
}
if (deb_check(prefix: 'netscape-base-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-base-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-base-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape-ja-resource-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-ja-resource-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-ja-resource-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape-java-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-java-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-java-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape-ko-resource-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-ko-resource-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-ko-resource-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape-smotif-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-smotif-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-smotif-477_4.77-2\n');
}
if (deb_check(prefix: 'netscape-zh-resource-477', release: '2.2', reference: '4.77-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netscape-zh-resource-477 is vulnerable in Debian 2.2.\nUpgrade to netscape-zh-resource-477_4.77-2\n');
}
if (w) { security_hole(port: 0, data: desc); }

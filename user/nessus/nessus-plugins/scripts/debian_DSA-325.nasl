# This script was automatically generated from the dsa-325
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
eldav, a WebDAV client for Emacs, creates temporary files without
taking appropriate security precautions.  This vulnerability could be
exploited by a local user to create or overwrite files with the
privileges of the user running emacs and eldav.
For the stable distribution (woody) this problem has been fixed in
version 0.0.20020411-1woody1.
The old stable distribution (potato) does not contain an eldav
package.
For the unstable distribution (sid) this problem has been fixed in
version 0.7.2-1.
We recommend that you update your eldav package.


Solution : http://www.debian.org/security/2003/dsa-325
Risk factor : High';

if (description) {
 script_id(15162);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "325");
 script_cve_id("CVE-2003-0438");
 script_bugtraq_id(7987);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA325] DSA-325-1 eldav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-325-1 eldav");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'eldav', release: '3.0', reference: '0.0.20020411-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eldav is vulnerable in Debian 3.0.\nUpgrade to eldav_0.0.20020411-1woody1\n');
}
if (deb_check(prefix: 'eldav', release: '3.1', reference: '0.7.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eldav is vulnerable in Debian 3.1.\nUpgrade to eldav_0.7.2-1\n');
}
if (deb_check(prefix: 'eldav', release: '3.0', reference: '0.0.20020411-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eldav is vulnerable in Debian woody.\nUpgrade to eldav_0.0.20020411-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

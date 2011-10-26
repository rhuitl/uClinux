# This script was automatically generated from the dsa-160
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Spybreak discovered a problem in scrollkeeper, a free electronic
cataloging system for documentation.  The scrollkeeper-get-cl program
creates temporary files in an insecure manner in /tmp using guessable
filenames.  Since scrollkeeper is called automatically when a user
logs into a Gnome session, an attacker with local access can easily
create and overwrite files as another user.
This problem has been fixed in version 0.3.6-3.1 for the current
stable distribution (woody) and in version 0.3.11-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn\'t contain the scrollkeeper package.
We recommend that you upgrade your scrollkeeper packages immediately.


Solution : http://www.debian.org/security/2002/dsa-160
Risk factor : High';

if (description) {
 script_id(14997);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "160");
 script_cve_id("CVE-2002-0662");
 script_bugtraq_id(5602);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA160] DSA-160-1 scrollkeeper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-160-1 scrollkeeper");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libscrollkeeper-dev', release: '3.0', reference: '0.3.6-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libscrollkeeper-dev is vulnerable in Debian 3.0.\nUpgrade to libscrollkeeper-dev_0.3.6-3.1\n');
}
if (deb_check(prefix: 'libscrollkeeper0', release: '3.0', reference: '0.3.6-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libscrollkeeper0 is vulnerable in Debian 3.0.\nUpgrade to libscrollkeeper0_0.3.6-3.1\n');
}
if (deb_check(prefix: 'scrollkeeper', release: '3.0', reference: '0.3.6-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package scrollkeeper is vulnerable in Debian 3.0.\nUpgrade to scrollkeeper_0.3.6-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

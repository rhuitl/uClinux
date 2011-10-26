# This script was automatically generated from the dsa-118
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tim Waugh found several insecure uses of temporary files in the xsane
program, which is used for scanning.  This was fixed for Debian/stable
by moving those files into a securely created directory within the
/tmp directory.
This problem has been fixed in version 0.50-5.1 for the stable Debian
distribution and in version 0.84-0.1 for the testing and unstable
distribution of Debian.
We recommend that you upgrade your xsane package.


Solution : http://www.debian.org/security/2002/dsa-118
Risk factor : High';

if (description) {
 script_id(14955);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "118");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA118] DSA-118-1 xsane");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-118-1 xsane");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xsane', release: '2.2', reference: '0.50-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xsane is vulnerable in Debian 2.2.\nUpgrade to xsane_0.50-5.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

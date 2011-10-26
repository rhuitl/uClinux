# This script was automatically generated from the dsa-100
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
GOBBLES found a buffer overflow in gzip that occurs when compressing
files with really long filenames.  Even though GOBBLES claims to have
developed an exploit to take advantage of this bug, it has been said
by others that this problem is not likely to be exploitable as other
security incidents.
Additionally, the Debian version of gzip from the stable release does
not segfault, and hence does not directly inherit this problem.
However, better be safe than sorry, so we have prepared an update for
you.
Please make sure you are running an up-to-date version from
stable/unstable/testing with at least version 1.2.4-33.


Solution : http://www.debian.org/security/2002/dsa-100
Risk factor : High';

if (description) {
 script_id(14937);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "100");
 script_cve_id("CVE-2001-1228");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA100] DSA-100-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-100-1 gzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gzip', release: '2.2', reference: '1.2.4-33.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 2.2.\nUpgrade to gzip_1.2.4-33.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

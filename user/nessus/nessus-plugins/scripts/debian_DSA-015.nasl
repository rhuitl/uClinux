# This script was automatically generated from the dsa-015
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Versions of the sash package prior to 3.4-4 did not clone
/etc/shadow properly, causing it to be made world-readable.

This package only exists in stable, so if you are running unstable you won\'t
see a bugfix unless you use the resources from the bottom of this message to
the proper configuration.

We recommend you upgrade your sash package immediately.


Solution : http://www.debian.org/security/2001/dsa-015
Risk factor : High';

if (description) {
 script_id(14852);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "015");
 script_cve_id("CVE-2001-0195");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA015] DSA-015-1 sash");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-015-1 sash");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sash', release: '2.2', reference: '3.4-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sash is vulnerable in Debian 2.2.\nUpgrade to sash_3.4-6\n');
}
if (w) { security_hole(port: 0, data: desc); }

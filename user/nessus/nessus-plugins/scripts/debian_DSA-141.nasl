# This script was automatically generated from the dsa-141
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eckehard Berns discovered a buffer overflow in the munpack program
which is used for decoding (respectively) binary files in MIME
(Multipurpose Internet Mail Extensions) format mail messages.  If
munpack is run on an appropriately malformed email (or news article)
then it will crash, and perhaps can be made to run arbitrary code.
Herbert Xu reported a second vulnerability which affected malformed
filenames that refer to files in upper directories like "../a".  The
security impact is limited, though, because only a single leading
"../" was accepted and only new files can be created (i.e. no files
will be overwritten).
Both problems have been fixed in version 1.5-5potato2 for the old
stable distribution (potato), in version 1.5-7woody2 for the current
stable distribution (woody) and in version 1.5-9 for the unstable
distribution (sid).
We recommend that you upgrade your mpack package immediately.


Solution : http://www.debian.org/security/2002/dsa-141
Risk factor : High';

if (description) {
 script_id(14978);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "141");
 script_cve_id("CVE-2002-1425");
 script_bugtraq_id(5385);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA141] DSA-141-1 mpack");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-141-1 mpack");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mpack', release: '2.2', reference: '1.5-5potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpack is vulnerable in Debian 2.2.\nUpgrade to mpack_1.5-5potato2\n');
}
if (deb_check(prefix: 'mpack', release: '3.0', reference: '1.5-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpack is vulnerable in Debian 3.0.\nUpgrade to mpack_1.5-7woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }

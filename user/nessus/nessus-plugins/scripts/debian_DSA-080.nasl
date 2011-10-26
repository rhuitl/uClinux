# This script was automatically generated from the dsa-080
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Nergal reported a <a
href="http://sourceforge.net/tracker/index.php?func=detail&amp;aid=458013&amp;group_id=4593&amp;atid=104593">vulnerability</a> in the htsearch program which is
distributed as part of the ht://Dig package, an indexing and searching
system for small domains or intranets.  Using former versions it was
able to pass the parameter -c to the cgi program in order to use a
different configuration file.

A malicious user could point htsearch to a file like
/dev/zero and
let the server run in an endless loop, trying to read config
parameters.  If the user has write permission on the server they can
point the program to it and retrieve any file readable by the webserver
user id.

This problem has been fixed in version 3.1.5-2.0potato.1 for Debian
GNU/Linux 2.2.

We recommend that you upgrade your htdig package immediately.



Solution : http://www.debian.org/security/2001/dsa-080
Risk factor : High';

if (description) {
 script_id(14917);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "080");
 script_cve_id("CVE-2001-0834");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA080] DSA-080-1 htdig");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-080-1 htdig");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'htdig', release: '2.2', reference: '3.1.5-2.0potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig is vulnerable in Debian 2.2.\nUpgrade to htdig_3.1.5-2.0potato.1\n');
}
if (deb_check(prefix: 'htdig-doc', release: '2.2', reference: '3.1.5-2.0potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htdig-doc is vulnerable in Debian 2.2.\nUpgrade to htdig-doc_3.1.5-2.0potato.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

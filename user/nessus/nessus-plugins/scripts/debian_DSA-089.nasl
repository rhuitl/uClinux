# This script was automatically generated from the dsa-089
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The icecast-server (a streaming music server) package as distributed
in Debian GNU/Linux 2.2 has several security problems:
These have been fixed in version 1.3.10-1, and we strongly recommend
that you upgrade your icecast-server package immediately.

The i386 package mentioned in the DSA-089-1 advisory was incorrectly
compiled and will not run on Debian GNU/Linux potato machines. This
has been corrected in version 1.3.10-1.1.



Solution : http://www.debian.org/security/2001/dsa-089
Risk factor : High';

if (description) {
 script_id(14926);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "089");
 script_cve_id("CVE-2001-1230", "CVE-2001-0784", "CVE-2001-1083");
 script_bugtraq_id(2264, 2932, 2933);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA089] DSA-089-2 icecast-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-089-2 icecast-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'icecast-server', release: '2.2', reference: '1.3.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package icecast-server is vulnerable in Debian 2.2.\nUpgrade to icecast-server_1.3.10-1\n');
}
if (w) { security_hole(port: 0, data: desc); }

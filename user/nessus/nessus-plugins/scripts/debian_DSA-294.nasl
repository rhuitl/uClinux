# This script was automatically generated from the dsa-294
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Brian Campbell discovered two security-related problems in
gkrellm-newsticker, a plugin for the gkrellm system monitor program,
which provides a news ticker from RDF feeds.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
For the stable distribution (woody) these problems have been fixed in
version 0.3-3.1.
The old stable distribution (potato) is not affected since it doesn\'t
contain gkrellm-newsticker packages.
For the unstable distribution (sid) these problems is not yet fixed.
We recommend that you upgrade your gkrellm-newsticker package.


Solution : http://www.debian.org/security/2003/dsa-294
Risk factor : High';

if (description) {
 script_id(15131);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "294");
 script_cve_id("CVE-2003-0205", "CVE-2003-0206");
 script_bugtraq_id(7414);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA294] DSA-294-1 gkrellm-newsticker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-294-1 gkrellm-newsticker");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gkrellm-newsticker', release: '3.0', reference: '0.3-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gkrellm-newsticker is vulnerable in Debian 3.0.\nUpgrade to gkrellm-newsticker_0.3-3.1\n');
}
if (deb_check(prefix: 'gkrellm-newsticker', release: '3.0', reference: '0.3-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gkrellm-newsticker is vulnerable in Debian woody.\nUpgrade to gkrellm-newsticker_0.3-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

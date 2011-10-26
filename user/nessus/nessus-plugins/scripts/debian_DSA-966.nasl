# This script was automatically generated from the dsa-966
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Thomas Reifferscheid discovered that adzapper, a proxy advertisement
zapper add-on, when installed as plugin in squid, the Internet object
cache, can consume a lot of CPU resources and hence cause a denial of
service on the proxy host.
The old stable distribution (woody) does not contain an adzapper package.
For the stable distribution (sarge) this problem has been fixed in
version 20050316-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 20060115-1.
We recommend that you upgrade your adzapper package.


Solution : http://www.debian.org/security/2006/dsa-966
Risk factor : High';

if (description) {
 script_id(22832);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "966");
 script_cve_id("CVE-2006-0046");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA966] DSA-966-1 adzapper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-966-1 adzapper");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'adzapper', release: '', reference: '20060115-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package adzapper is vulnerable in Debian .\nUpgrade to adzapper_20060115-1\n');
}
if (deb_check(prefix: 'adzapper', release: '3.1', reference: '20050316-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package adzapper is vulnerable in Debian 3.1.\nUpgrade to adzapper_20050316-1sarge1\n');
}
if (deb_check(prefix: 'adzapper', release: '3.1', reference: '20050316-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package adzapper is vulnerable in Debian sarge.\nUpgrade to adzapper_20050316-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }

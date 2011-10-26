# This script was automatically generated from the dsa-532
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in libapache-mod-ssl:
  Stack-based buffer overflow in the
  ssl_util_uuencode_binary function in ssl_util.c for Apache mod_ssl,
  when mod_ssl is configured to trust the issuing CA, may allow remote
  attackers to execute arbitrary code via a client certificate with a
  long subject DN.
  Format string vulnerability in the ssl_log function
  in ssl_engine_log.c in mod_ssl 2.8.19 for Apache 1.3.31 may allow
  remote attackers to execute arbitrary messages via format string
  specifiers in certain log messages for HTTPS.
For the current stable distribution (woody), these problems have been
fixed in version 2.8.9-2.4.
For the unstable distribution (sid), CVE-2004-0488 was fixed in
version 2.8.18, and CVE-2004-0700 will be fixed soon.
We recommend that you update your libapache-mod-ssl package.


Solution : http://www.debian.org/security/2004/dsa-532
Risk factor : High';

if (description) {
 script_id(15369);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "532");
 script_cve_id("CVE-2004-0488", "CVE-2004-0700");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA532] DSA-532-2 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-532-2 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl_2.8.9-2.4\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl-doc_2.8.9-2.4\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.1', reference: '2.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-ssl_2.8\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian woody.\nUpgrade to libapache-mod-ssl_2.8.9-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }

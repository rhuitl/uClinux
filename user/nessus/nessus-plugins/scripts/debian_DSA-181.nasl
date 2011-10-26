# This script was automatically generated from the dsa-181
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joe Orton discovered a cross site scripting problem in mod_ssl, an
Apache module that adds Strong cryptography (i.e. HTTPS support) to
the webserver.  The module will return the server name unescaped in
the response to an HTTP request on an SSL port.
Like the other recent Apache XSS bugs, this only affects servers using
a combination of "UseCanonicalName off" (default in the Debian package
of Apache) and wildcard DNS.  This is very unlikely to happen, though.
Apache 2.0/mod_ssl is not vulnerable since it already escapes this
HTML.
With this setting turned on, whenever Apache needs to construct a
self-referencing URL (a URL that refers back to the server the
response is coming from) it will use ServerName and Port to form a
"canonical" name.  With this setting off, Apache will use the
hostname:port that the client supplied, when possible.  This also
affects SERVER_NAME and SERVER_PORT in CGI scripts.
This problem has been fixed in version 2.8.9-2.1 for the current
stable distribution (woody), in version 2.4.10-1.3.9-1potato4 for the
old stable distribution (potato) and version 2.8.9-2.3 for the
unstable distribution (sid).
We recommend that you upgrade your libapache-mod-ssl package.


Solution : http://www.debian.org/security/2002/dsa-181
Risk factor : High';

if (description) {
 script_id(15018);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "181");
 script_cve_id("CVE-2002-1157");
 script_bugtraq_id(6029);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA181] DSA-181-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-181-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl_2.4.10-1.3.9-1potato4\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl-doc_2.4.10-1.3.9-1potato4\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl_2.8.9-2.1\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl-doc_2.8.9-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

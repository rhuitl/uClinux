# This script was automatically generated from the dsa-135
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The libapache-mod-ssl package provides SSL capability to the apache
webserver.
Recently, a problem has been found in the handling of .htaccess files,
allowing arbitrary code execution as the web server user (regardless of
ExecCGI / suexec settings), DoS attacks (killing off apache children), and
allowing someone to take control of apache child processes - all through
specially crafted .htaccess files.
This has been fixed in the libapache-mod-ssl_2.4.10-1.3.9-1potato2 package
(for potato), and the libapache-mod-ssl_2.8.9-2 package (for woody).
We recommend you upgrade as soon as possible.


Solution : http://www.debian.org/security/2002/dsa-135
Risk factor : High';

if (description) {
 script_id(14972);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "135");
 script_cve_id("CVE-2002-0653");
 script_bugtraq_id(5084);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA135] DSA-135-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-135-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl_2.4.10-1.3.9-1potato2\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 2.2.\nUpgrade to libapache-mod-ssl-doc_2.4.10-1.3.9-1potato2\n');
}
if (deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl_2.8.9-2\n');
}
if (deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-ssl-doc is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-ssl-doc_2.8.9-2\n');
}
if (w) { security_hole(port: 0, data: desc); }

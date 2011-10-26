# This script was automatically generated from the dsa-063
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
zen-parse reported on bugtraq that there is a possible buffer overflow
in the logging code from xinetd. This could be triggered by using a
fake identd that returns special replies when xinetd does an ident
request. 

Another problem is that xinetd sets it umask to 0. As a result any
programs that xinetd start that are not careful with file permissions
will create world-writable files.

Both problems have been fixed in version 2.1.8.8.p3-1.1.



Solution : http://www.debian.org/security/2001/dsa-063
Risk factor : High';

if (description) {
 script_id(14900);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "063");
 script_cve_id("CVE-2001-0763", "CVE-2001-1322");
 script_bugtraq_id(2826, 2840);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA063] DSA-063-1 xinetd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-063-1 xinetd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xinetd', release: '2.2', reference: '2.1.8.8.p3-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xinetd is vulnerable in Debian 2.2.\nUpgrade to xinetd_2.1.8.8.p3-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

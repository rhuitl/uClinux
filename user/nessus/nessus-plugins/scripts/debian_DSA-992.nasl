# This script was automatically generated from the dsa-992
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Simon Kilvington discovered that specially crafted PNG images can trigger
a heap overflow in libavcodec, the multimedia library of ffmpeg, which may
lead to the execution of arbitrary code.
The old stable distribution (woody) doesn\'t contain ffmpeg packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.cvs20050313-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.cvs20050918-5.1.
We recommend that you upgrade your ffmpeg package.


Solution : http://www.debian.org/security/2006/dsa-992
Risk factor : High';

if (description) {
 script_id(22858);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "992");
 script_cve_id("CVE-2005-4048");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA992] DSA-992-1 ffmpeg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-992-1 ffmpeg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ffmpeg', release: '', reference: '0.cvs20050918-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ffmpeg is vulnerable in Debian .\nUpgrade to ffmpeg_0.cvs20050918-5.1\n');
}
if (deb_check(prefix: 'ffmpeg', release: '3.1', reference: '0.cvs20050313-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ffmpeg is vulnerable in Debian 3.1.\nUpgrade to ffmpeg_0.cvs20050313-2sarge1\n');
}
if (deb_check(prefix: 'libavcodec-dev', release: '3.1', reference: '0.cvs20050313-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libavcodec-dev is vulnerable in Debian 3.1.\nUpgrade to libavcodec-dev_0.cvs20050313-2sarge1\n');
}
if (deb_check(prefix: 'libavformat-dev', release: '3.1', reference: '0.cvs20050313-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libavformat-dev is vulnerable in Debian 3.1.\nUpgrade to libavformat-dev_0.cvs20050313-2sarge1\n');
}
if (deb_check(prefix: 'libpostproc-dev', release: '3.1', reference: '0.cvs20050313-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpostproc-dev is vulnerable in Debian 3.1.\nUpgrade to libpostproc-dev_0.cvs20050313-2sarge1\n');
}
if (deb_check(prefix: 'ffmpeg', release: '3.1', reference: '0.cvs20050313-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ffmpeg is vulnerable in Debian sarge.\nUpgrade to ffmpeg_0.cvs20050313-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-017
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'With older versions of jazip a user could gain root
access for members of the floppy group to the local machine. The interface
doesn\'t run as root anymore and this very exploit was prevented. The program
now also truncates DISPLAY to 256 characters if it is bigger, which closes the
buffer overflow (within xforms). 
We recommend you upgrade your jazip package immediately.  


Solution : http://www.debian.org/security/2001/dsa-017
Risk factor : High';

if (description) {
 script_id(14854);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "017");
 script_cve_id("CVE-2001-0110");
 script_bugtraq_id(2209);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA017] DSA-017-1 jazip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-017-1 jazip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'jazip', release: '2.2', reference: '0.33-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package jazip is vulnerable in Debian 2.2.\nUpgrade to jazip_0.33-1\n');
}
if (w) { security_hole(port: 0, data: desc); }

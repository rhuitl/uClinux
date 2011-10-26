# This script was automatically generated from the dsa-163
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jason Molenda and Hiromitsu Takagi
found
ways to exploit cross site
scripting bugs in mhonarc, a mail to HTML converter.  When processing
maliciously crafted mails of type text/html mhonarc does not
deactivate all scripting parts properly.  This is fixed in upstream
version 2.5.3.
If you are worried about security, it is recommended that you disable
support of text/html messages in your mail archives.  There is no
guarantee that the mhtxthtml.pl library is robust enough to eliminate
all possible exploits that can occur with HTML data.
To exclude HTML data, you can use the MIMEEXCS resource.  For example:

    <MIMEExcs>
    text/html
    text/x-html
    </MIMEExcs>


The type "text/x-html" is probably not used any more, but is good to
include it, just-in-case.
If you are concerned that this could block out the entire contents of
some messages, then you could do the following instead:

    <MIMEFilters>
    text/html; m2h_text_plain::filter; mhtxtplain.pl
    text/x-html; m2h_text_plain::filter; mhtxtplain.pl
    </MIMEFilters>


This treats the HTML as text/plain.
The above problems have been fixed in version 2.5.2-1.1 for the
current stable distribution (woody), in version 2.4.4-1.1 for
the old stable distribution (potato) and in version 2.5.11-1 for the
unstable distribution (sid).
We recommend that you upgrade your mhonarc packages.


Solution : http://www.debian.org/security/2002/dsa-163
Risk factor : High';

if (description) {
 script_id(15000);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "163");
 script_cve_id("CVE-2002-0738");
 script_bugtraq_id(4546);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA163] DSA-163-1 mhonarc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-163-1 mhonarc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mhonarc', release: '2.2', reference: '2.4.4-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 2.2.\nUpgrade to mhonarc_2.4.4-1.1\n');
}
if (deb_check(prefix: 'mhonarc', release: '3.0', reference: '2.5.2-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mhonarc is vulnerable in Debian 3.0.\nUpgrade to mhonarc_2.5.2-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

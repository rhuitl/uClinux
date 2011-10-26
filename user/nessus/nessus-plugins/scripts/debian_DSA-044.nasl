# This script was automatically generated from the dsa-044
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'The mail program (a simple tool to read and send
email) as distributed with Debian GNU/Linux 2.2 has a buffer overflow
in the input parsing code. Since mail is installed setgid mail by
default this allowed local users to use it to gain access to mail
group.

Since the mail code was never written to be secure fixing it
properly would mean a large rewrite. Instead of doing this we decided
to no longer install it setgid. This means that it can no longer lock
your mailbox properly on systems for which you need group mail to
write to the mailspool, but it will still work for sending email.

This has been fixed in mailx version 8.1.1-10.1.5. If you have
suidmanager installed you can also make this manually with the
following command:
suidregister /usr/bin/mail root root 0755



Solution : http://www.debian.org/security/2001/dsa-044
Risk factor : High';

if (description) {
 script_id(14881);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "044");
 script_bugtraq_id(2457);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA044] DSA-044-1 mailx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-044-1 mailx");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailx', release: '2.2', reference: '8.1.1-10.1.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailx is vulnerable in Debian 2.2.\nUpgrade to mailx_8.1.1-10.1.5\n');
}
if (w) { security_hole(port: 0, data: desc); }

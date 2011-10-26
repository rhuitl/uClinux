# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16409);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-18");
 script_cve_id("CVE-2004-1165");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-18
(KDE FTP KIOslave: Command injection)


    The FTP KIOslave fails to properly parse URL-encoded newline
    characters.
  
Impact

    An attacker could exploit this to execute arbitrary FTP commands on the
    server and due to similiarities between the FTP and the SMTP protocol,
    this vulnerability also allows an attacker to connect to a SMTP server
    and issue arbitrary commands, for example sending an email.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.kde.org/info/security/advisory-20050101-1.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1165


Solution: 
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdelibs
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-18] KDE FTP KIOslave: Command injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE FTP KIOslave: Command injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.3.2-r2", "rge 3.2.3-r5"), vulnerable: make_list("lt 3.3.2-r2")
)) { security_warning(0); exit(0); }

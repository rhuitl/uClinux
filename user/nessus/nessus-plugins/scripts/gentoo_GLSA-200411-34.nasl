# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-34.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15833);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-34");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-34
(Cyrus IMAP Server: Multiple remote vulnerabilities)


    Multiple vulnerabilities have been discovered in the argument
    parsers of the \'partial\' and \'fetch\' commands of the Cyrus IMAP Server
    (CVE-2004-1012, CVE-2004-1013). There are also buffer overflows in the
    \'imap magic plus\' code that are vulnerable to exploitation as well
    (CVE-2004-1011, CVE-2004-1015).
  
Impact

    An attacker can exploit these vulnerabilities to execute arbitrary
    code with the rights of the user running the Cyrus IMAP Server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1011
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1012
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1013
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1015
    http://security.e-matters.de/advisories/152004.html
    http://asg.web.cmu.edu/cyrus/download/imapd/changes.html


Solution: 
    All Cyrus-IMAP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/cyrus-imapd-2.2.10"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-34] Cyrus IMAP Server: Multiple remote vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus IMAP Server: Multiple remote vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/cyrus-imapd", unaffected: make_list("ge 2.2.10"), vulnerable: make_list("lt 2.2.10")
)) { security_hole(0); exit(0); }

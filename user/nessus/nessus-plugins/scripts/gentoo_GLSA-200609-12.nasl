# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22429);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-12");
 script_cve_id("CVE-2006-2941");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-12
(Mailman: Multiple vulnerabilities)


    Mailman fails to properly handle standards-breaking RFC 2231 formatted
    headers. Furthermore, Moritz Naumann discovered several XSS
    vulnerabilities and a log file injection.
  
Impact

    An attacker could exploit these vulnerabilities to cause Mailman to
    stop processing mails, to inject content into the log file or to
    execute arbitrary scripts running in the context of the administrator
    or mailing list user\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2941
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2006-3636


Solution: 
    All Mailman users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailman-2.1.9_rc1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-12] Mailman: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailman: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/mailman", unaffected: make_list("ge 2.1.9_rc1"), vulnerable: make_list("lt 2.1.9_rc1")
)) { security_warning(0); exit(0); }

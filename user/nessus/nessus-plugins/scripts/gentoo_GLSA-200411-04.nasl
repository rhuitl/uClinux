# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15607);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-04");
 script_cve_id("CVE-2004-0834");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-04
(Speedtouch USB driver: Privilege escalation vulnerability)


    The Speedtouch USB driver contains multiple format string vulnerabilities
    in modem_run, pppoa2 and pppoa3. This flaw is due to an improperly made
    syslog() system call.
  
Impact

    A malicious local user could exploit this vulnerability by causing a buffer
    overflow, and potentially allowing the execution of arbitrary code with
    escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0834
    http://speedtouch.sourceforge.net/index.php?/news.en.html


Solution: 
    All Speedtouch USB driver users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/speedtouch-1.3.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-04] Speedtouch USB driver: Privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Speedtouch USB driver: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-dialup/speedtouch", unaffected: make_list("ge 1.3.1"), vulnerable: make_list("lt 1.3.1")
)) { security_hole(0); exit(0); }

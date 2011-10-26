# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21021);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-04");
 script_cve_id("CVE-2005-2661");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-04
(IMAP Proxy: Format string vulnerabilities)


    Steve Kemp discovered two format string errors in IMAP Proxy.
  
Impact

    A remote attacker could design a malicious IMAP server and entice
    someone to connect to it using IMAP Proxy, resulting in the execution
    of arbitrary code with the rights of the victim user.
  
Workaround

    Only connect to trusted IMAP servers using IMAP Proxy.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2661


Solution: 
    All IMAP Proxy users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/up-imapproxy-1.2.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-04] IMAP Proxy: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IMAP Proxy: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/up-imapproxy", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14548);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-15
(Opera: Multiple spoofing vulnerabilities)


    Opera fails to remove illegal characters from an URI of a link and to check
    that the target frame of a link belongs to the same website as the link.
    Opera also updates the address bar before loading a page. Additionally,
    Opera contains a certificate verification problem.
  
Impact

    These vulnerabilities could allow an attacker to impersonate legitimate
    websites to steal sensitive information from users. This could be done by
    obfuscating the real URI of a link or by injecting a malicious frame into
    an arbitrary frame of another browser window.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://www.securityfocus.com/bid/10517
    http://secunia.com/advisories/11978/
    http://secunia.com/advisories/12028/
    http://www.opera.com/linux/changelogs/753/


Solution: 
    All Opera users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-www/opera-7.53"
    # emerge ">=net-www/opera-7.53"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-15] Opera: Multiple spoofing vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple spoofing vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/opera", unaffected: make_list("ge 7.53"), vulnerable: make_list("le 7.52")
)) { security_warning(0); exit(0); }

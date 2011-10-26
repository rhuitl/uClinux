# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14482);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200404-17");
 script_cve_id("CVE-2004-0403");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-17
(ipsec-tools and iputils contain a remote DoS vulnerability)


    When racoon receives an ISAKMP header, it allocates memory based on the
    length of the header field. Thus, an attacker may be able to cause a Denial
    of Services by creating a header that is large enough to consume all
    available system resources.
  
Impact

    This vulnerability may allow an attacker to remotely cause a Denial of
    Service.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://ipsec-tools.sourceforge.net/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0403


Solution: 
    ipsec-tools users should upgrade to version 0.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.3.1"
    # emerge ">=net-firewall/ipsec-tools-0.3.1"
    iputils users should upgrade to version 021109-r3 or later:
    # emerge sync
    # emerge -pv ">=net-misc/iputils-021109-r3"
    # emerge ">=net-misc/iputils-021109-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-17] ipsec-tools and iputils contain a remote DoS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ipsec-tools and iputils contain a remote DoS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/ipsec-tools", arch: "amd64", unaffected: make_list("ge 0.3.1"), vulnerable: make_list("lt 0.3.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-misc/iputils", arch: "ppc amd64 ppc64 s390", unaffected: make_list("eq 021109-r3"), vulnerable: make_list("eq 021109-r1")
)) { security_warning(0); exit(0); }

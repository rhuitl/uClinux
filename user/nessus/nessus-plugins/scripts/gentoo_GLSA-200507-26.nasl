# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19328);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-26
(GNU Gadu, CenterICQ, Kadu, EKG, libgadu: Remote code execution in Gadu library)


    GNU Gadu, CenterICQ, Kadu, EKG and libgadu are vulnerable to an
    integer overflow.
  
Impact

    A remote attacker could exploit the integer overflow to execute
    arbitrary code or cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1852
    http://www.securityfocus.com/archive/1/406026/30/


Solution: 
    All GNU Gadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gnugadu-2.2.6-r1"
    All Kadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/kadu-0.4.1"
    All EKG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/ekg-1.6_rc3"
    All libgadu users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/libgadu-20050719"
    All CenterICQ users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/centericq-4.20.0-r3"
    CenterICQ is no longer distributed with Gadu Gadu support,
    affected users are encouraged to migrate to an alternative package.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-26] GNU Gadu, CenterICQ, Kadu, EKG, libgadu: Remote code execution in Gadu library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU Gadu, CenterICQ, Kadu, EKG, libgadu: Remote code execution in Gadu library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gnugadu", unaffected: make_list("ge 2.2.6-r1"), vulnerable: make_list("lt 2.2.6-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-im/ekg", unaffected: make_list("ge 1.6_rc3"), vulnerable: make_list("lt 1.6_rc3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-im/kadu", unaffected: make_list("ge 0.4.1"), vulnerable: make_list("lt 0.4.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-libs/libgadu", unaffected: make_list("ge 20050719"), vulnerable: make_list("lt 20050719")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-im/centericq", unaffected: make_list("ge 4.20.0-r3"), vulnerable: make_list("lt 4.20.0-r3")
)) { security_hole(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14579);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-23
(kdelibs: Cross-domain cookie injection vulnerability)


    kcookiejar contains a vulnerability which may allow a malicious website to
    set cookies for other websites under the same second-level domain.
    This vulnerability applies to country-specific secondary top level domains
    that use more than 2 characters in the secondary part of the domain name,
    and that use a secondary part other than com, net, mil, org, gov, edu or
    int. However, certain popular domains, such as co.uk, are not affected.
  
Impact

    Users visiting a malicious website using the Konqueror browser may have a
    session cookie set for them by that site. Later, when the user visits
    another website under the same domain, the attacker\'s session cookie will
    be used instead of the cookie issued by the legitimate site. Depending on
    the design of the legitimate site, this may allow an attacker to gain
    access to the user\'s session. For further explanation on this type of
    attack, see the paper titled "Session Fixation Vulnerability in
    Web-based Applications" (reference 2).
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of kdelibs.
  
References:
    http://www.kde.org/info/security/advisory-20040823-1.txt
    http://www.acros.si/papers/session_fixation.pdf


Solution: 
    All kdelibs users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=kde-base/kdelibs-3.2.3-r2"
    # emerge ">=kde-base/kdelibs-3.2.3-r2"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-23] kdelibs: Cross-domain cookie injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kdelibs: Cross-domain cookie injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.2.3-r2"), vulnerable: make_list("le 3.2.3-r1")
)) { security_warning(0); exit(0); }

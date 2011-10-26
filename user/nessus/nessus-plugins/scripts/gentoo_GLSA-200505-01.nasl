# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18170);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-01
(Horde Framework: Multiple XSS vulnerabilities)


    Cross-site scripting vulnerabilities have been discovered in
    various modules of the Horde Framework.
  
Impact

    These vulnerabilities could be exploited by an attacker to execute
    arbitrary HTML and script code in context of the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://marc.theaimsgroup.com/?l=horde-announce&r=1&b=200504&w=2


Solution: 
    All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-2.2.8"
    All Horde Vacation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-vacation-2.2.2"
    All Horde Turba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-turba-1.2.5"
    All Horde Passwd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-passwd-2.2.2"
    All Horde Nag users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-nag-1.1.3"
    All Horde Mnemo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-mnemo-1.1.4"
    All Horde Kronolith users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-kronolith-1.1.4"
    All Horde IMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-imp-3.2.8"
    All Horde Accounts users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-accounts-2.1.2"
    All Horde Forwards users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-forwards-2.2.2"
    All Horde Chora users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-chora-1.2.3"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-01] Horde Framework: Multiple XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Framework: Multiple XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/horde-turba", unaffected: make_list("ge 1.2.5"), vulnerable: make_list("lt 1.2.5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-accounts", unaffected: make_list("ge 2.1.2"), vulnerable: make_list("lt 2.1.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-vacation", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 2.2.8"), vulnerable: make_list("lt 2.2.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-imp", unaffected: make_list("ge 3.2.8"), vulnerable: make_list("lt 3.2.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-mnemo", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-forwards", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-chora", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-kronolith", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-nag", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-passwd", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_warning(0); exit(0); }

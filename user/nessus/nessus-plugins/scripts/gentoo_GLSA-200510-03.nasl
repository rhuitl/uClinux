# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19849);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-03
(Uim: Privilege escalation vulnerability)


    Masanari Yamamoto discovered that Uim uses environment variables
    incorrectly. This bug causes a privilege escalation if setuid/setgid
    applications are linked to libuim. This bug only affects
    immodule-enabled Qt (if you build Qt 3.3.2 or later versions with
    USE="immqt" or USE="immqt-bc").
  
Impact

    A malicious local user could exploit this vulnerability to execute
    arbitrary code with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.freedesktop.org/pipermail/uim/2005-September/001346.html


Solution: 
    All Uim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-i18n/uim-0.4.9.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-03] Uim: Privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Uim: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-i18n/uim", unaffected: make_list("ge 0.4.9.1"), vulnerable: make_list("lt 0.4.9.1")
)) { security_warning(0); exit(0); }

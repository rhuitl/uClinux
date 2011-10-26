# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17234);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-31");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-31
(uim: Privilege escalation vulnerability)


    Takumi Asaki discovered that uim insufficiently checks environment
    variables. setuid/setgid applications linked against libuim could end
    up executing arbitrary code. This vulnerability only affects
    immodule-enabled Qt (if you build Qt 3.3.2 or later versions with
    USE="immqt" or USE="immqt-bc").
  
Impact

    A malicious local user could exploit this vulnerability to execute
    arbitrary code with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0503
    http://lists.freedesktop.org/archives/uim/2005-February/000996.html


Solution: 
    All uim users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-i18n/uim-0.4.5.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-31] uim: Privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'uim: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-i18n/uim", unaffected: make_list("ge 0.4.5.1"), vulnerable: make_list("lt 0.4.5.1")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14497);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-11");
 script_cve_id("CVE-2004-0411");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-11
(KDE URI Handler Vulnerabilities)


    The telnet, rlogin, ssh and mailto URI handlers in KDE do not check for \'-\'
    at the beginning of the hostname passed. By crafting a malicious URI and
    entice an user to click on it, it is possible to pass an option to the
    programs started by the handlers (typically telnet, kmail...).
  
Impact

    If the attacker controls the options passed to the URI handling programs,
    it becomes possible for example to overwrite arbitrary files (possibly
    leading to denial of service), to open kmail on an attacker-controlled
    remote display or with an alternate configuration file (possibly leading to
    control of the user account).
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to a corrected version of kdelibs.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0411


Solution: 
    Users of KDE 3.1 should upgrade to the corrected version of kdelibs:
    # emerge sync
    # emerge -pv "=kde-base/kdelibs-3.1.5-r1"
    # emerge "=kde-base/kdelibs-3.1.5-r1"
    Users of KDE 3.2 should upgrade to the latest available version of kdelibs:
    # emerge sync
    # emerge -pv ">=kde-base/kdelibs-3.2.2-r1"
    # emerge ">=kde-base/kdelibs-3.2.2-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-11] KDE URI Handler Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE URI Handler Vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.2.2-r1", "eq 3.1.5-r1"), vulnerable: make_list("le 3.2.2")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18529);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-14
(Sun and Blackdown Java: Applet privilege escalation)


    Both Sun\'s and Blackdown\'s JDK and JRE may allow untrusted applets
    to elevate privileges.
  
Impact

    A remote attacker could embed a malicious Java applet in a web
    page and entice a victim to view it. This applet can then bypass
    security restrictions and execute any command or access any file with
    the rights of the user running the web browser.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
    http://www.blackdown.org/java-linux/java2-status/security/Blackdown-SA-2005-02.txt


Solution: 
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.08"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.08"
    All Blackdown JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/blackdown-jdk-1.4.2.02"
    All Blackdown JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/blackdown-jre-1.4.2.02"
    Note to SPARC users: There is no stable secure Blackdown Java
    for the SPARC architecture. Affected users should remove the package
    until a SPARC package is released.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-14] Sun and Blackdown Java: Applet privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun and Blackdown Java: Applet privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-java/blackdown-jre", unaffected: make_list("ge 1.4.2.02"), vulnerable: make_list("lt 1.4.2.02")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.08"), vulnerable: make_list("lt 1.4.2.08")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/blackdown-jdk", unaffected: make_list("ge 1.4.2.02"), vulnerable: make_list("lt 1.4.2.02")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.08"), vulnerable: make_list("lt 1.4.2.08")
)) { security_warning(0); exit(0); }

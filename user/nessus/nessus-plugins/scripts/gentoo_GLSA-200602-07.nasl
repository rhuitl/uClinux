# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20921);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-07
(Sun JDK/JRE: Applet privilege escalation)


    Applets executed using JRE or JDK can use "reflection" APIs
    functions to elevate its privileges beyond the sandbox restrictions.
    Adam Gowdiak discovered five vulnerabilities that use this method for
    privilege escalation. Two more vulnerabilities were discovered by the
    vendor. Peter Csepely discovered that Web Start Java applications also
    can an escalate their privileges.
  
Impact

    A malicious Java applet can bypass Java sandbox restrictions and
    hence access local files, connect to arbitrary network locations and
    execute arbitrary code on the user\'s machine. Java Web Start
    applications are affected likewise.
  
Workaround

    Select another Java implementation using java-config.
  
References:
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-102170-1
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-102171-1
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0614
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0615
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0616
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0617


Solution: 
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.10"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.10"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-07] Sun JDK/JRE: Applet privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Applet privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.10"), vulnerable: make_list("lt 1.4.2.10")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.10"), vulnerable: make_list("lt 1.4.2.10")
)) { security_warning(0); exit(0); }

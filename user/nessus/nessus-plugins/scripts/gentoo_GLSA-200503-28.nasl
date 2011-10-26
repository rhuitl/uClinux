# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17615);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200503-28");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-28
(Sun Java: Web Start argument injection vulnerability)


    Jouko Pynnonen discovered that Java Web Start contains a
    vulnerability in the way it handles property tags in JNLP files.
  
Impact

    By enticing a user to open a malicious JNLP file, a remote
    attacker could pass command line arguments to the Java Virtual machine,
    which can be used to bypass the Java "sandbox" and to execute arbitrary
    code with the permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://jouko.iki.fi/adv/ws.html
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-57740-1


Solution: 
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.07"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.07"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-28] Sun Java: Web Start argument injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun Java: Web Start argument injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.07", "lt 1.4.2"), vulnerable: make_list("lt 1.4.2.07")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.07", "lt 1.4.2"), vulnerable: make_list("lt 1.4.2.07")
)) { security_warning(0); exit(0); }

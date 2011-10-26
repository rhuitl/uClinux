# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14517);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200406-06");
 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-06
(CVS: additional DoS and arbitrary code execution vulnerabilities)


    A team audit of the CVS source code performed by Stefan Esser and Sebastian
    Krahmer resulted in the discovery of several remotely exploitable
    vulnerabilities including:
    no-null-termination of "Entry" lines
    error_prog_name "double-free()"
    Argument integer overflow
    serve_notify() out of bounds writes
  
Impact

    An attacker could use these vulnerabilities to cause a Denial of Service or
    execute arbitrary code with the permissions of the user running cvs.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of CVS.
  
References:
    http://security.e-matters.de/advisories/092004.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0414
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0416
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0417
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0418


Solution: 
    All CVS users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-util/cvs-1.11.17"
    # emerge ">=dev-util/cvs-1.11.17"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-06] CVS: additional DoS and arbitrary code execution vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS: additional DoS and arbitrary code execution vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.17"), vulnerable: make_list("le 1.11.16-r1")
)) { security_hole(0); exit(0); }

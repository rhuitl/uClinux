# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16422);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-31");
 script_cve_id("CVE-2004-0888", "CVE-2004-0889", "CVE-2004-1125", "CVE-2005-0064");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-31
(teTeX, pTeX, CSTeX: Multiple vulnerabilities)


    teTeX, pTeX and CSTeX all make use of Xpdf code and may therefore
    be vulnerable to the various overflows that were discovered in Xpdf
    code (CVE-2004-0888, CVE-2004-0889, CVE-2004-1125 and CVE-2005-0064).
    Furthermore, Javier Fernandez-Sanguino Pena discovered that the
    xdvizilla script does not handle temporary files correctly.
  
Impact

    An attacker could design a malicious input file which, when
    processed using one of the TeX distributions, could lead to the
    execution of arbitrary code. Furthermore, a local attacker could create
    symbolic links in the temporary files directory, pointing to a valid
    file somewhere on the filesystem. When xdvizilla is called, this would
    result in the file being overwritten with the rights of the user
    running the script.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0888
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0889
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1125
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0064


Solution: 
    All teTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/tetex-2.0.2-r5"
    All CSTeX users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/cstetex-2.0.2-r1"
    Finally, all pTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ptex-3.1.4-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-31] teTeX, pTeX, CSTeX: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'teTeX, pTeX, CSTeX: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/tetex", unaffected: make_list("ge 2.0.2-r5"), vulnerable: make_list("lt 2.0.2-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/cstetex", unaffected: make_list("ge 2.0.2-r1"), vulnerable: make_list("lt 2.0.2-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/ptex", unaffected: make_list("ge 3.1.4-r2"), vulnerable: make_list("lt 3.1.4-r2")
)) { security_warning(0); exit(0); }

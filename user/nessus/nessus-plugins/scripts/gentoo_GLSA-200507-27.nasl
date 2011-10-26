# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19329);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-27
(Ethereal: Multiple vulnerabilities)


    There are numerous vulnerabilities in versions of Ethereal prior
    to 0.10.12, including:
    The SMB dissector could overflow a
    buffer or exhaust memory (CVE-2005-2365).
    iDEFENSE discovered
    that several dissectors are vulnerable to format string overflows
    (CVE-2005-2367).
    Additionally multiple potential crashes in
    many dissectors have been fixed, see References for further
    details.
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal or execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.ethereal.com/appnotes/enpa-sa-00020.html
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2360
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2361
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2362
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2363
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2364
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2365
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2366
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2367


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.12"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-27] Ethereal: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.12"), vulnerable: make_list("lt 0.10.12")
)) { security_hole(0); exit(0); }

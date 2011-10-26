# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21195);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-02");
 script_cve_id("CVE-2006-1260", "CVE-2006-1491");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-02
(Horde Application Framework: Remote code execution)


    Jan Schneider of the Horde team discovered a vulnerability in the
    help viewer of the Horde Application Framework that could allow remote
    code execution (CVE-2006-1491). Paul Craig reported that
    "services/go.php" fails to validate the passed URL parameter correctly
    (CVE-2006-1260).
  
Impact

    An attacker could exploit the vulnerability in the help viewer to
    execute arbitrary code with the privileges of the web server user. By
    embedding a NULL character in the URL parameter, an attacker could
    exploit the input validation issue in go.php to read arbitrary files.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1260
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1491
    http://lists.horde.org/archives/announce/2006/000271.html


Solution: 
    All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-3.1.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-02] Horde Application Framework: Remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Application Framework: Remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1")
)) { security_hole(0); exit(0); }

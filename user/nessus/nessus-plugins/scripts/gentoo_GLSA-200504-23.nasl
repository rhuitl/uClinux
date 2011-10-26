# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18126);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-23");
 script_cve_id("CVE-2005-0754");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-23
(Kommander: Insecure remote script execution)


    Kommander executes data files from possibly untrusted locations without
    user confirmation.
  
Impact

    An attacker could exploit this to execute arbitrary code with the
    permissions of the user running Kommander.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0754
    http://www.kde.org/info/security/advisory-20050420-1.txt


Solution: 
    All kdewebdev users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdewebdev-3.3.2-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-23] Kommander: Insecure remote script execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kommander: Insecure remote script execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdewebdev", unaffected: make_list("ge 3.3.2-r2"), vulnerable: make_list("lt 3.3.2-r2")
)) { security_warning(0); exit(0); }

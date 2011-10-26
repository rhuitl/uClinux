# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21351);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-09");
 script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-09
(Mozilla Thunderbird: Multiple vulnerabilities)


    Several vulnerabilities were found and fixed in Mozilla
    Thunderbird.
  
Impact

    A remote attacker could craft malicious emails that would leverage
    these issues to inject and execute arbitrary script code with elevated
    privileges, steal local files or other information from emails, and
    spoof content. Some of these vulnerabilities might even be exploited to
    execute arbitrary code with the rights of the user running Thunderbird.
  
Workaround

    There are no known workarounds for all the issues at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0292
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0296
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0748
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0749
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0884
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1045
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1727
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1728
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1730
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1731
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1732
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1733
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1734
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1735
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1737
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1738
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1739
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1741
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1742
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1790
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird


Solution: 
    All Mozilla Thunderbird users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.0.8"
    All Mozilla Thunderbird binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.0.8"
    Note: There is no stable fixed version for the ALPHA
    architecture yet. Users of Mozilla Thunderbird on ALPHA should consider
    unmerging it until such a version is available.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-09] Mozilla Thunderbird: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8")
)) { security_warning(0); exit(0); }

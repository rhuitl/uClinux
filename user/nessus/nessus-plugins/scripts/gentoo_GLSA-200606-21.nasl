# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21734);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-21");
 script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2786", "CVE-2006-2787");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-21
(Mozilla Thunderbird: Multiple vulnerabilities)


    Several vulnerabilities were found and fixed in Mozilla Thunderbird.
    For details, please consult the references below.
  
Impact

    A remote attacker could craft malicious emails that would leverage
    these issues to inject and execute arbitrary script code with elevated
    privileges, spoof content, and possibly execute arbitrary code with the
    rights of the user running the application.
  
Workaround

    There are no known workarounds for all the issues at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2775
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2776
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2778
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2779
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2780
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2781
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2783
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2786
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2787
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird


Solution: 
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.5.0.4"
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.5.0.4"
    Note: There is no stable fixed version for the Alpha architecture yet.
    Users of Mozilla Thunderbird on Alpha should consider unmerging it
    until such a version is available.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-21] Mozilla Thunderbird: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.5.0.4"), vulnerable: make_list("lt 1.5.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.5.0.4"), vulnerable: make_list("lt 1.5.0.4")
)) { security_warning(0); exit(0); }

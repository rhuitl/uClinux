# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17619);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-30");
 script_cve_id("CVE-2004-1156", "CVE-2005-0230", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0588", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-30
(Mozilla Suite: Multiple vulnerabilities)

Impact

    The GIF heap overflow could be triggered by a malicious GIF
    image that would end up executing arbitrary code with the rights of the
    user running Mozilla. The other overflow issues, while not thought to
    be exploitable, would have the same impact
    By setting up
    malicious websites and convincing users to follow untrusted links or
    obey very specific drag-and-drop or download instructions, attackers
    may leverage the various spoofing issues to fake other websites to get
    access to confidential information, push users to download malicious
    files or make them interact with their browser preferences
    The
    temporary directory issue allows local attackers to overwrite arbitrary
    files with the rights of another local user
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1156
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0230
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0231
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0232
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0233
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0255
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0399
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0401
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0527
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0578
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0584
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0585
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0588
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0590
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0591
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0592
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0593
    http://www.mozilla.org/projects/security/known-vulnerabilities.html


Solution: 
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.6"
    All Mozilla Suite binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-30] Mozilla Suite: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Suite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.6"), vulnerable: make_list("lt 1.7.6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.6"), vulnerable: make_list("lt 1.7.6")
)) { security_warning(0); exit(0); }

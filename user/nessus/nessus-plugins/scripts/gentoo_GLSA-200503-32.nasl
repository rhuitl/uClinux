# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-32.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17632);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-32");
 script_cve_id("CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0590", "CVE-2005-0592");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-32
(Mozilla Thunderbird: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in Mozilla
    Thunderbird:
    Mark Dowd from ISS X-Force reported an
    exploitable heap overrun in the GIF processing of obsolete Netscape
    extension 2 (CVE-2005-0399)
    Daniel de Wildt and Gael Delalleau
    discovered a memory overwrite in a string library (CVE-2005-0255)
    Wind Li discovered a possible heap overflow in UTF8 to Unicode
    conversion (CVE-2005-0592)
    Phil Ringnalda reported a possible
    way to spoof Install source with user:pass@host (CVE-2005-0590)
  
Impact

    The GIF heap overflow could be triggered by a malicious GIF image
    that would end up executing arbitrary code with the rights of the user
    running Thunderbird. The other overflow issues, while not thought to be
    exploitable, would have the same impact. Furthermore, by setting up
    malicious websites and convincing users to follow untrusted links,
    attackers may leverage the spoofing issue to trick user into installing
    malicious extensions.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0255
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0399
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0590
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0592
    http://www.mozilla.org/projects/security/known-vulnerabilities.html


Solution: 
    All Mozilla Thunderbird users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.0.2"
    All Mozilla Thunderbird binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.0.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-32] Mozilla Thunderbird: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_warning(0); exit(0); }

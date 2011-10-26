# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-42.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16433);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-42");
 script_cve_id("CVE-2005-0071");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-42
(VDR: Arbitrary file overwriting issue)


    Javier Fernandez-Sanguino Pena from the Debian Security Audit Team
    discovered that VDR accesses user-controlled files insecurely.
  
Impact

    A local attacker could create malicious links and invoke a VDR
    recording that would overwrite arbitrary files on the system.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0071


Solution: 
    All VDR users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vdr-1.2.6-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-42] VDR: Arbitrary file overwriting issue");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VDR: Arbitrary file overwriting issue');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/vdr", unaffected: make_list("ge 1.2.6-r1"), vulnerable: make_list("lt 1.2.6-r1")
)) { security_warning(0); exit(0); }

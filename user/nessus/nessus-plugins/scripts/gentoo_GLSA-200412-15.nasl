# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16002);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-15");
 script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-15
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier
    than 0.10.8, including:
    Bug in DICOM dissection
    discovered by Bing could make Ethereal crash (CAN 2004-1139).
    An invalid RTP timestamp could make Ethereal hang and create a
    large temporary file (CAN 2004-1140).
    The HTTP dissector could
    access previously-freed memory (CAN 2004-1141).
    Brian Caswell
    discovered that an improperly formatted SMB could make Ethereal hang
    (CAN 2004-1142).
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal, perform DoS by CPU and disk space utilization or even execute
    arbitrary code with the permissions of the user running Ethereal, which
    could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. However, it is strongly recommended to upgrade to
    the latest stable version.
  
References:
    http://www.ethereal.com/appnotes/enpa-sa-00016.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1139
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1140
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1141
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1142


Solution: 
    All ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.8"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-15] Ethereal: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.8"), vulnerable: make_list("lt 0.10.8")
)) { security_hole(0); exit(0); }

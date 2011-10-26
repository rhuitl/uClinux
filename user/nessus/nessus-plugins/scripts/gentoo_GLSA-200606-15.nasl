# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21708);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-15");
 script_cve_id("CVE-2006-2898");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-15
(Asterisk: IAX2 video frame buffer overflow)


    Asterisk fails to properly check the length of truncated video frames
    in the IAX2 channel driver which results in a buffer overflow.
  
Impact

    An attacker could exploit this vulnerability by sending a specially
    crafted IAX2 video stream resulting in the execution of arbitrary code
    with the permissions of the user running Asterisk.
  
Workaround

    Disable public IAX2 support.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2898
    http://www.coresecurity.com/common/showdoc.php?idx=547&idxseccion=10


Solution: 
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/asterisk-1.0.11_p1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-15] Asterisk: IAX2 video frame buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: IAX2 video frame buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("ge 1.0.11_p1"), vulnerable: make_list("lt 1.0.11_p1")
)) { security_hole(0); exit(0); }

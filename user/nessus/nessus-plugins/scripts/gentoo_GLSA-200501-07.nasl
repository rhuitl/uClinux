# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16398);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-07");
 script_cve_id("CVE-2004-1187", "CVE-2004-1188", "CVE-2004-1300");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-07
(xine-lib: Multiple overflows)


    Ariel Berkman discovered that xine-lib reads specific input data
    into an array without checking the input size in demux_aiff.c, making
    it vulnerable to a buffer overflow (CVE-2004-1300) . iDefense
    discovered that the PNA_TAG handling code in pnm_get_chunk() does not
    check if the input size is larger than the buffer size (CVE-2004-1187).
    iDefense also discovered that in this same function, a negative value
    could be given to an unsigned variable that specifies the read length
    of input data (CVE-2004-1188).
  
Impact

    A remote attacker could craft a malicious movie or convince a
    targeted user to connect to a malicious PNM server, which could result
    in the execution of arbitrary code with the rights of the user running
    any xine-lib frontend.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1187
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1188
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1300
    http://www.idefense.com/application/poi/display?id=176&type=vulnerabilities
    http://www.idefense.com/application/poi/display?id=177&type=vulnerabilities
    http://tigger.uic.edu/~jlongs2/holes/xine-lib.txt


Solution: 
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/xine-lib
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-07] xine-lib: Multiple overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Multiple overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc8-r1", "rge 1_rc6-r1"), vulnerable: make_list("lt 1_rc8-r1")
)) { security_warning(0); exit(0); }

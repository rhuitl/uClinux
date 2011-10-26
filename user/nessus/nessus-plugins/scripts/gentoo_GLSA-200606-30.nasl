# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21791);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-30");
 script_cve_id("CVE-2006-2923");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-30
(Kiax: Arbitrary code execution)


    The iax_net_read function in the iaxclient library fails to properly
    handle IAX2 packets with truncated full frames or mini-frames. These
    frames are detected in a length check but processed anyway, leading to
    buffer overflows.
  
Impact

    By sending a specially crafted IAX2 packet, an attacker could execute
    arbitrary code with the permissions of the user running Kiax.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2923


Solution: 
    All Kiax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/kiax-0.8.5_p1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-30] Kiax: Arbitrary code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kiax: Arbitrary code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/kiax", unaffected: make_list("ge 0.8.5_p1"), vulnerable: make_list("lt 0.8.5_p1")
)) { security_warning(0); exit(0); }

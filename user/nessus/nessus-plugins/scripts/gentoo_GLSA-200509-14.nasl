# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19813);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200509-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-14
(Zebedee: Denial of Service vulnerability)


     "Shiraishi.M" reported that Zebedee crashes when "0" is received
    as the port number in the protocol option header.
  
Impact

    By performing malformed requests a remote attacker could cause
    Zebedee to crash.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/bid/14796


Solution: 
    All Zebedee users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/zebedee
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-14] Zebedee: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Zebedee: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/zebedee", unaffected: make_list("rge 2.4.1-r1", "ge 2.5.3"), vulnerable: make_list("lt 2.5.3")
)) { security_warning(0); exit(0); }

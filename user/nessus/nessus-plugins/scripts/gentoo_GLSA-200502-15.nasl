# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16452);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-15
(PowerDNS: Denial of Service vulnerability)


    A vulnerability has been reported in the DNSPacket::expand method
    of dnspacket.cc.
  
Impact

    An attacker could cause a temporary Denial of Service by sending a
    random stream of bytes to the PowerDNS Daemon.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://doc.powerdns.com/changelog.html#CHANGELOG-2-9-17
    http://ds9a.nl/cgi-bin/cvstrac/pdns/tktview?tn=21


Solution: 
    All PowerDNS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/pdns-2.9.17"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-15] PowerDNS: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PowerDNS: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-dns/pdns", unaffected: make_list("ge 2.9.17"), vulnerable: make_list("lt 2.9.17")
)) { security_warning(0); exit(0); }

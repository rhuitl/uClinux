# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19212);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-16");
 script_cve_id("CVE-2005-1848");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-16
(dhcpcd: Denial of Service vulnerability)


    infamous42md discovered that dhcpcd can be tricked to read past
    the end of the supplied DHCP buffer. As a result, this might lead to a
    crash of the daemon.
  
Impact

    With a malicious DHCP server an attacker could cause a Denial of
    Service by crashing the DHCP client.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1848


Solution: 
    All dhcpcd users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/dhcpcd-1.3.22_p4-r11"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-16] dhcpcd: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'dhcpcd: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/dhcpcd", unaffected: make_list("ge 1.3.22_p4-r11"), vulnerable: make_list("lt 1.3.22_p4-r11")
)) { security_warning(0); exit(0); }

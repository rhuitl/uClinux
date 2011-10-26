# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-36.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17666);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-36");
 script_cve_id("CVE-2005-0469");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-36
(netkit-telnetd: Buffer overflow)


    A buffer overflow has been identified in the slc_add_reply()
    function of netkit-telnetd client, where a large number of SLC commands
    can overflow a fixed size buffer.
  
Impact

    Successful explotation would require a vulnerable user to connect
    to an attacker-controlled host using telnet, potentially executing
    arbitrary code with the permissions of the telnet user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0469
    http://www.idefense.com/application/poi/display?id=220&type=vulnerabilities


Solution: 
    All netkit-telnetd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/netkit-telnetd-0.17-r6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-36] netkit-telnetd: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'netkit-telnetd: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/netkit-telnetd", unaffected: make_list("ge 0.17-r6"), vulnerable: make_list("lt 0.17-r6")
)) { security_warning(0); exit(0); }

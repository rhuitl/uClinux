# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14470);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-05
(ipsec-tools contains an X.509 certificates vulnerability.)


    racoon (a utility in the ipsec-tools package) does not verify digital
    signatures on Phase1 packets.  This means  that anybody holding the correct
    X.509 certificate would be able to establish a connection, even if they did
    not have the corresponding private key.
  
Impact

    Since digital signatures are not verified by the racoon tool, an attacker may
	be able to connect to the VPN gateway and/or execute a man-in-the-middle attack.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  

Solution: 
    ipsec-tools users should upgrade to version 0.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.2.5"
    # emerge ">=net-firewall/ipsec-tools-0.2.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-05] ipsec-tools contains an X.509 certificates vulnerability.");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ipsec-tools contains an X.509 certificates vulnerability.');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/ipsec-tools", arch: "amd64", unaffected: make_list("ge 0.2.5"), vulnerable: make_list("le 0.2.4")
)) { security_hole(0); exit(0); }

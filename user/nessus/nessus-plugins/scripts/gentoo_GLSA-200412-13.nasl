# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15997);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-13");
 script_cve_id("CVE-2004-1154");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-13
(Samba: Integer overflow)


    Samba contains a bug when unmarshalling specific MS-RPC requests from
    clients.
  
Impact

    A remote attacker may be able to execute arbitrary code with the
    permissions of the user running Samba, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1154
    http://www.samba.org/samba/security/CAN-2004-1154.html


Solution: 
    All samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.9-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-13] Samba: Integer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Integer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.9-r1"), vulnerable: make_list("le 3.0.9")
)) { security_hole(0); exit(0); }

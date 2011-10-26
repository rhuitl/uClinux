# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14540);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-07
(Shorewall : Insecure temp file handling)


    Shorewall uses temporary files and directories in an insecure manner. A
    local user could create symbolic links at specific locations, eventually
    overwriting other files on the filesystem with the rights of the shorewall
    process.
  
Impact

    An attacker could exploit this vulnerability to overwrite arbitrary system
    files with root privileges, resulting in Denial of Service or further
    exploitation.
  
Workaround

    There is no known workaround at this time. All users should upgrade to the
    latest available version of Shorewall.
  
References:
    http://lists.shorewall.net/pipermail/shorewall-announce/2004-June/000385.html


Solution: 
    All users should upgrade to the latest available version of Shorewall, as
    follows:
    # emerge sync
    # emerge -pv ">=net-firewall/shorewall-1.4.10f"
    # emerge ">=net-firewall/shorewall-1.4.10f"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-07] Shorewall : Insecure temp file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shorewall : Insecure temp file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/shorewall", unaffected: make_list("ge 1.4.10f"), vulnerable: make_list("le 1.4.10c")
)) { security_warning(0); exit(0); }

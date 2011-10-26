# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15969);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-09");
 script_cve_id("CVE-2004-1079");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-09
(ncpfs: Buffer overflow in ncplogin and ncpmap)


    Karol Wiesek discovered a buffer overflow in the handling of the
    \'-T\' option in the ncplogin and ncpmap utilities, which are both
    installed as SUID root by default.
  
Impact

    A local attacker could trigger the buffer overflow by calling one
    of these utilities with a carefully crafted command line, potentially
    resulting in execution of arbitrary code with root privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.netsys.com/pipermail/full-disclosure/2004-November/029563.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1079


Solution: 
    All ncpfs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/ncpfs-2.2.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-09] ncpfs: Buffer overflow in ncplogin and ncpmap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ncpfs: Buffer overflow in ncplogin and ncpmap');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/ncpfs", unaffected: make_list("ge 2.2.5"), vulnerable: make_list("lt 2.2.5")
)) { security_hole(0); exit(0); }

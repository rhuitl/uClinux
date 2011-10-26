# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15567);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200410-25");
 script_cve_id("CVE-2004-0974");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-25
(Netatalk: Insecure tempfile handling in etc2ps.sh)


    The etc2ps.sh script creates temporary files in world-writeable directories
    with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    etc2ps.sh is executed, this would result in the file being overwritten with
    the rights of the user running the utility, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0974


Solution: 
    All Netatalk users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/netatalk-1.6.4-r1"
    # emerge ">=net-fs/netatalk-1.6.4-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-25] Netatalk: Insecure tempfile handling in etc2ps.sh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Netatalk: Insecure tempfile handling in etc2ps.sh');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/netatalk", unaffected: make_list("ge 1.6.4-r1"), vulnerable: make_list("lt 1.6.4-r1")
)) { security_warning(0); exit(0); }

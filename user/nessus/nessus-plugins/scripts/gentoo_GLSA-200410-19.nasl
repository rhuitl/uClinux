# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15538);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-19");
 script_cve_id("CVE-2004-0968");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-19
(glibc: Insecure tempfile handling in catchsegv script)


    The catchsegv script creates temporary files in world-writeable directories
    with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    catchsegv script is called, this would result in the file being overwritten
    with the rights of the user running the utility, which could be the root
    user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0968


Solution: 
    All glibc users should upgrade to the latest version:
    # emerge sync
    # emerge -pv sys-libs/glibc
    # emerge sys-libs/glibc
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-19] glibc: Insecure tempfile handling in catchsegv script");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'glibc: Insecure tempfile handling in catchsegv script');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-libs/glibc", unaffected: make_list("rge 2.2.5-r9", "rge 2.3.2-r12", "rge 2.3.3.20040420-r2", "rge 2.3.4.20040619-r2", "ge 2.3.4.20040808-r1"), vulnerable: make_list("le 2.3.4.20040808")
)) { security_warning(0); exit(0); }

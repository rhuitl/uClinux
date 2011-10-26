# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15777);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-29");
 script_cve_id("CVE-2004-0947", "CVE-2004-1027");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-29
(unarj: Long filenames buffer overflow and a path traversal vulnerability)


    unarj has a bounds checking vulnerability within the handling of
    long filenames in archives. It also fails to properly sanitize paths
    when extracting an archive (if the "x" option is used to preserve
    paths).
  
Impact

    An attacker could trigger a buffer overflow or a path traversal by
    enticing a user to open an archive containing specially-crafted path
    names, potentially resulting in the overwrite of files or execution of
    arbitrary code with the permissions of the user running unarj.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0947
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1027


Solution: 
    All unarj users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/unarj-2.63a-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-29] unarj: Long filenames buffer overflow and a path traversal vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'unarj: Long filenames buffer overflow and a path traversal vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/unarj", unaffected: make_list("ge 2.63a-r2"), vulnerable: make_list("lt 2.63a-r2")
)) { security_warning(0); exit(0); }

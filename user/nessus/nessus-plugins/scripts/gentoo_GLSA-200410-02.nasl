# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15418);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-02");
 script_cve_id("CVE-2003-0924");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-02
(Netpbm: Multiple temporary file issues)


    Utilities contained in the Netpbm package prior to the 9.25 version contain
    defects in temporary file handling. They create temporary files with
    predictable names without checking first that the target file doesn\'t
    already exist.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When a
    user or a tool calls one of the affected utilities, this would result in
    file overwriting with the rights of the user running the utility.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0924
    http://www.kb.cert.org/vuls/id/487102


Solution: 
    All Netpbm users should upgrade to an unaffected version:
    # emerge sync
    # emerge -pv ">=media-libs/netpbm-10.0"
    # emerge ">=media-libs/netpbm-10.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-02] Netpbm: Multiple temporary file issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Netpbm: Multiple temporary file issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/netpbm", unaffected: make_list("ge 10.0"), vulnerable: make_list("le 9.12-r4")
)) { security_warning(0); exit(0); }

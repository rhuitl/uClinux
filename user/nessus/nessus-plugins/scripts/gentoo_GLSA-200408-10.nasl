# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14566);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200408-10");
 script_cve_id("CVE-2002-0838");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-10
(gv: Exploitable Buffer Overflow)


    gv contains a buffer overflow vulnerability where an unsafe sscanf() call
    is used to interpret PDF and PostScript files.
  
Impact

    By enticing a user to view a malformed PDF or PostScript file an attacker
    could execute arbitrary code with the permissions of the user running gv.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of gv.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0838


Solution: 
    All gv users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-text/gv-3.5.8-r4"
    # emerge ">=app-text/gv-3.5.8-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-10] gv: Exploitable Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gv: Exploitable Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/gv", unaffected: make_list("ge 3.5.8-r4"), vulnerable: make_list("le 3.5.8-r3")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22169);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-11");
 script_cve_id("CVE-2006-3392");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-11
(Webmin, Usermin: File Disclosure)


    A vulnerability in both Webmin and Usermin has been discovered by Kenny
    Chen, wherein simplify_path is called before the HTML is decoded.
  
Impact

    A non-authenticated user can read any file on the server using a
    specially crafted URL.
  
Workaround

    For a temporary workaround, IP Access Control can be setup on Webmin
    and Usermin.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392


Solution: 
    All Webmin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/webmin-1.290"
    All Usermin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot ">=app-admin/usermin-1.220"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-11] Webmin, Usermin: File Disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: File Disclosure');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.220"), vulnerable: make_list("lt 1.220")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.290"), vulnerable: make_list("lt 1.290")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22216);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-17");
 script_cve_id("CVE-2006-3376");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-17
(libwmf: Buffer overflow vulnerability)


    infamous41md discovered that libwmf fails to do proper bounds checking
    on the MaxRecordSize variable in the WMF file header. This could lead
    to an head-based buffer overflow.
  
Impact

    By enticing a user to open a specially crafted WMF file, a remote
    attacker could cause a heap-based buffer overflow and execute arbitrary
    code with the permissions of the user running the application that uses
    libwmf.
  
Workaround

    There is no known workaround for this issue.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3376


Solution: 
    All libwmf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libwmf-0.2.8.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-17] libwmf: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libwmf: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/libwmf", unaffected: make_list("ge 0.2.8.4"), vulnerable: make_list("lt 0.2.8.4")
)) { security_warning(0); exit(0); }

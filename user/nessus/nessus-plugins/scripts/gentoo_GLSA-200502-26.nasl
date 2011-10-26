# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17145);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-26
(GProFTPD: gprostats format string vulnerability)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has
    identified a format string vulnerability in the gprostats utility.
  
Impact

    An attacker could exploit the vulnerability by performing a
    specially crafted FTP transfer, the resulting ProFTPD transfer log
    could potentially trigger the execution of arbitrary code when parsed
    by GProFTPD.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All GProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/gproftpd-8.1.9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-26] GProFTPD: gprostats format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GProFTPD: gprostats format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/gproftpd", unaffected: make_list("ge 8.1.9"), vulnerable: make_list("lt 8.1.9")
)) { security_warning(0); exit(0); }

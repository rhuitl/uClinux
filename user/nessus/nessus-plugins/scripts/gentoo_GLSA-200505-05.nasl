# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18231);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-05");
 script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-05
(gzip: Multiple vulnerabilities)


    The gzip and gunzip programs are vulnerable to a race condition
    when setting file permissions (CVE-2005-0988), as well as improper
    handling of filename restoration (CVE-2005-1228). The zgrep utility
    improperly sanitizes arguments, which may come from an untrusted source
    (CVE-2005-0758).
  
Impact

    These vulnerabilities could allow arbitrary command execution,
    changing the permissions of arbitrary files, and installation of files
    to an aribitrary location in the filesystem.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0758
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0988
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1228


Solution: 
    All gzip users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/gzip-1.3.5-r6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-05] gzip: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gzip: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/gzip", unaffected: make_list("ge 1.3.5-r6"), vulnerable: make_list("lt 1.3.5-r6")
)) { security_warning(0); exit(0); }

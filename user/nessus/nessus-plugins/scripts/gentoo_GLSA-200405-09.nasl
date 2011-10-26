# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14495);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-09");
 script_cve_id("CVE-2004-0432");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-09
(ProFTPD Access Control List bypass vulnerability)


    ProFTPD 1.2.9 introduced a vulnerability that allows CIDR-based ACLs (such
    as 10.0.0.1/24) to be bypassed. The CIDR ACLs are disregarded, with the net
    effect being similar to an "AllowAll" directive.
  
Impact

    This vulnerability may allow unauthorized files, including critical system
    files to be downloaded and/or modified, thereby allowing a potential remote
    compromise of the server.
  
Workaround

    Users may work around the problem by avoiding use of CIDR-based ACLs.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0432


Solution: 
    ProFTPD users are encouraged to upgrade to the latest version of the
    package:
    # emerge sync
    # emerge -pv ">=net-ftp/proftpd-1.2.9-r2"
    # emerge ">=net-ftp/proftpd-1.2.9-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-09] ProFTPD Access Control List bypass vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD Access Control List bypass vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.2.9-r2"), vulnerable: make_list("eq 1.2.9-r1", "eq 1.2.9")
)) { security_hole(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-38.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16429);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-38");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-38
(Perl: rmtree and DBI tmpfile vulnerabilities)


    Javier Fernandez-Sanguino Pena discovered that the DBI library creates
    temporary files in an insecure, predictable way (CVE-2005-0077). Paul
    Szabo found out that "File::Path::rmtree" is vulnerable to various race
    conditions (CVE-2004-0452, CVE-2005-0448).
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory that point to a valid file somewhere on the filesystem. When
    the DBI library or File::Path::rmtree is executed, this could be used
    to overwrite or remove files with the rights of the user calling these
    functions.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0452
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0077
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0448


Solution: 
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
    All DBI library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-perl/DBI
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-38] Perl: rmtree and DBI tmpfile vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: rmtree and DBI tmpfile vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-perl/DBI", unaffected: make_list("rge 1.37-r1", "ge 1.38-r1"), vulnerable: make_list("le 1.38")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.6-r4", "rge 5.8.5-r5", "rge 5.8.4-r4", "rge 5.8.2-r4"), vulnerable: make_list("le 5.8.6-r3")
)) { security_warning(0); exit(0); }

#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:030
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21723);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:030: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:030 (postgresql).


Two character set encoding related security problems were fixed in the
PostgreSQL database server:

CVE-2006-2313:
Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling
of invalidly-encoded multibyte text data. If a client application
processed untrusted input without respecting its encoding and
applied standard string escaping techniques (such as replacing a
single quote >>'<< with >>\'<< or >>''<<), the PostgreSQL server
could interpret the resulting string in a way that allowed an
attacker to inject arbitrary SQL commands into the resulting SQL
query. The PostgreSQL server has been modified to reject such
invalidly encoded strings now, which completely fixes the problem
for some 'safe' multibyte encodings like UTF-8.

CVE-2006-2314:
However, there are some less popular and client-only multibyte
encodings (such as SJIS, BIG5, GBK, GB18030, and UHC) which
contain valid multibyte characters that end with the byte 0x5c,
which is the representation of the backslash character >>\<< in
ASCII. Many client libraries and applications use the non-standard,
but popular way of escaping the >>'<< character by replacing all
occurrences of it with >>\'<<. If a client application uses one of
the affected encodings and does not interpret multibyte characters,
and an attacker supplies a specially crafted byte sequence as an
input string parameter, this escaping method would then produce a
validly-encoded character and an excess >>'<< character which would
end the string. All subsequent characters would then be interpreted
as SQL code, so the attacker could execute arbitrary SQL commands.

To fix this vulnerability end-to-end, client-side applications
must be fixed to properly interpret multibyte encodings and use
>>''<< instead of >>\'<<. However, as a precautionary measure,
the sequence >>\'<< is now regarded as invalid when one of the
affected client encodings is in use. If you depend on the previous
behavior, you can restore it by setting 'backslash_quote = on'
in postgresql.conf.  However, please be aware that this could
render you vulnerable again.

This issue does not affect you if you only use single-byte (like
SQL_ASCII or the ISO-8859-X family) or unaffected multibyte
(like UTF-8) encodings.

Please see http://www.postgresql.org/docs/techdocs.50 for further
details.

Unfortunately we are not yet able to provide back ported patches for
the PostgreSQL included in SUSE Linux Enterprise Server 8 at this
time. We are working on a solution for this problem.


Solution : http://www.suse.de/security/advisories/2006_30_postgresql.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"postgresql-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.13-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.13-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}

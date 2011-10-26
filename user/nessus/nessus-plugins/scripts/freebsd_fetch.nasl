#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15761);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(11702);
 name["english"] = "FreeBSD : SA-04:16.fetch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of FreeBSD which contains a flaw in the 
'fetch' utility.

'fetch' is a command-line tool used to retrieve data at a given URL. It is used
(among others) by the FreeBSD port collection.

There is an integer overflow condition in the processing of HTTP headers
which may result in a buffer overflow.

An attacker may exploit this flaw to execute arbitrary commands on the remote
host. To exploit this flaw, an attacker would need to lure a victim on the remote
host into downloading a URL from a malicious web server using this utility.

Solution : http://www.vuxml.org/freebsd/759b8dfe-3972-11d9-a9e7-0001020eed82.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the FreeBSD";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


package = get_kb_item("Host/FreeBSD/release");

if ( ! package ) exit(0);

if ( egrep(pattern:"FreeBSD-5\.3", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.3_1") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_12") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.1", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.1.1_18") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.0", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.0_22") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-7]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.7_28") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.8", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_26") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_13") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.10", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_4") < 0 )
 {
  security_hole(port);
  exit(0);
 }
}


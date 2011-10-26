#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17633);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-2005-0892", "CVE-2005-0893");
 script_bugtraq_id(12899, 12922);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"15066");
 }
 
 name["english"] = "Smail-3 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote mail server is affected by multiple vulnerabilities. 

Description :

According to its banner, the remote host is running as its mail server
S-mail version 3.2.0.120 or older.  Such versions contain various
vulnerabilities that may allow an unauthenticated attacker to execute
arbitrary code on the remote host by exploiting a heap overflow by
sending a malformed argument to the 'MAIL FROM' command. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0435.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0459.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0462.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0474.html 
ftp://ftp.weird.com/pub/local/smail-3.2.0.121.ChangeLog

Solution : 

Upgrade to Smail 3.2.0.121 or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the version of the remote Smail daemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
  
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpscan.nasl");
 
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('smtp_func.inc');
port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if ( ! banner )exit(0);
if ( ereg(pattern:".* Smail(-)?3\.([01]\.|2\.0\.([0-9] |[0-9][0-9] |1[01][0-9] |120 ))", string:banner) ) security_hole(port);

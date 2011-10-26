#
# (C) Tenable Network Security
#
# Ref: 
# From: Stefan Esser <s.esser@e-matters.de>
# Message-ID: <20021212112625.GA431@php.net>
# To: full-disclosure@lists.netsys.com
# Cc: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Advisory 04/2002: Multiple MySQL vulnerabilities
#
# URL:
# http://security.e-matters.de/advisories/042002.html 
#

if(description)
{
 
 script_id(11192);  
 script_bugtraq_id(6368, 6370, 6373, 6374, 6375, 8796);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2002:288-22");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:003");

 
 name["english"] = "Multiple MySQL flaws";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote database server may be disabled remotely

Description :

The remote host is running a version of MySQL older than 3.23.54 or 4.0.6.

The remote version of this product contains several flaw which may allow an attacker
to crash this service remotely.

See also : 

http://security.e-matters.de/advisories/042002.html

Solution : 

Upgrade to the latest version of MySQL

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 - 2006 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver = get_mysql_version(port:port); 
if (isnull(ver)) exit(0);

if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-3])[^0-9])",
  	  string:ver))security_hole(port);	  
else if(ereg(pattern:"^4\.0\.[0-5][^0-9]", string:ver))security_hole(port);	  

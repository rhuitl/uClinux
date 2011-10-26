#
# (C) Tenable Network Security
# 
if(description)
{
 script_id(11870);
 script_bugtraq_id(1055);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2000-0199");
 name["english"] = "Microsoft's SQL version less than or equal to 7";
 script_name(english:name["english"]);
 
 desc["english"] = "
Based on version number, the remote host may be vulnerable to a local exploit 
wherein authenticated user can obtain and crack SQL username and password 
from the registry

An attacker may use this flaw to elevate their privileges on the local database.

*** This alert might be a false positive, as Nessus did not actually
*** check for this flaw but solely relied on the presence of MS SQL 7 to
*** issue this alert


Solution: Ensure that the configuration has enabled Always prompting for 
login name and password

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft SQL less than or equal to 7 may be misconfigured";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports(1433, "Services/mssql");
 script_dependencie("mssqlserver_detect.nasl", "mssql_version.nasl"); 
 exit(0);
}

port=1433;
version = get_kb_item("mssql/SQLVersion");
if(version)
{
 if (egrep(pattern:"^[67]\..*" , string:version)) security_warning(port);
}

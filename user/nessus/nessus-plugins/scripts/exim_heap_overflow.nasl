#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11828);
 script_bugtraq_id(8518);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0743");
 
 name["english"] = "Exim Heap Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the Exim MTA which is as old
as, or older than 4.21

There is a vulnerability in this server which might allow an attacker
to gain a shell on this host, although it currently is considered as being
unexploitable.

Solution : Upgrade to Exim 4.22
Risk factor : High";

 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the version of the remote Exim daemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"220.*Exim ([0-3]\.|4\.([0-9][^0-9]|1[0-9][^0-9]|2[01][^0-9]))", string:banner))security_hole(port);

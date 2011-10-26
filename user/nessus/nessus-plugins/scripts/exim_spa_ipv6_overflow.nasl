#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16111);
 script_cve_id("CVE-2005-0022");
 script_bugtraq_id(12185,12188);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Exim Illegal IPv6 Address and SPA Authentication Buffer Overflow Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Exim, a message transfer agent (SMTP).
It is reported that Exim is prone to an IPv6 Address and a SPA
authentication buffer Overflow . An attacker, exploiting those flaws,
may be able to execute arbitrary code on the remote host.

Exim must be configured with SPA Authentication or with IPv6 support
to exploit those flaws.

Solution : Upgrade to Exim latest version
Risk factor : High";

 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Exim Illegal IPv6 Address and SPA Authentication Buffer Overflow Vulnerabilities";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port) port = 25;
if (! get_port_state(port)) exit(0);

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if ( "Exim" >!< banner  ) exit(0);

if(egrep(pattern:"220.*Exim ([0-3]\.|4\.([0-9][^0-9]|[0-3][0-9]|4[0-3][^0-9]))", string:banner))
        security_hole(port);


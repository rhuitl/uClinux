#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence: GPLv2
#

if(description)
{
 script_id(11321);
 script_bugtraq_id(5845);
 script_cve_id("CVE-2002-1165", "CVE-2002-1337");
 script_version ("$Revision: 1.10 $");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:073-06");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:023");

 
 name["english"] = "Sendmail 8.8.8 to 8.12.7 Double Pipe Access Validation Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
smrsh (supplied by Sendmail) is designed to prevent the execution of
commands outside of the restricted environment. However, when commands
are entered using either double pipes (||) or a mixture of dot
and slash characters, a user may be able to bypass the checks
performed by smrsh. This can lead to the execution of commands
outside of the restricted environment.

Solution : upgrade to the latest version of Sendmail (or at least 8.12.8).
Risk factor : Medium"; 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks sendmail's version number"; 
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
                 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
                  francais:"Ce script est Copyright (C) 2003 StrongHoldNet");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner)
{
 if(egrep(pattern:"Sendmail.*(8\.8\.[89]|8\.9\..*|8\.1[01]\.*|8\.12\.[0-7][^0-9])/", string:banner))
        security_warning(port);
}


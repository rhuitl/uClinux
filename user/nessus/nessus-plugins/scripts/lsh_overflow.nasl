#
# (C) Tenable Network Security
#
#
# Ref:
# From: Haggis <haggis@learningshophull.co.uk>
# To: bugtraq@securityfocus.com
# Subject: Remote root vuln in lsh 1.4.x
# Date: Fri, 19 Sep 2003 13:01:24 +0000
# Message-Id: <200309191301.24607.haggis@haggis.kicks-ass.net>

if(description)
{
 script_id(11843);
 script_bugtraq_id(8655);
 script_version ("$Revision: 1.4 $");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:041");

 
 name["english"] = "lsh overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of LSH (a free replacement for
SSH) which is older than 1.5.3

Versions older than 1.5.3 are vulnerable to a buffer overflow which
may allow an attacker to gain a root shell on this host.


Solution : Upgrade to lsh 1.5.3 or to OpenSSH
Risk factor : High";
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

if(egrep(pattern:".*lshd[-_](0\..*|1\.[0-4]\.|1\.5\.[0-2])", string:banner, icase:TRUE)) security_hole(port);

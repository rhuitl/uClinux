#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10378);
 script_bugtraq_id(1131);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0295");
 name["english"] = "LCDproc buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A buffer overflow in the remote LCDproc server may allow an attacker
to execute arbitrary code on the remote host.

Description :

The remote LCDproc service is vulnerable to a buffer overflow vulnerability
when processing commands received from the network due to a lack of bound
checks.

An attacker may exploit this flaw to execute arbitrary code on the remote host,
with the privileges of the LCDproc process (usually, nobody).

Solution : 

Upgrade to LCDproc 0.4.1 or newer

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "LCDproc version check";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("lcdproc_detect.nasl");
  script_require_ports("Services/lcdproc", 13666);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if(!port)port = 13666;

version = get_kb_item("lcdproc/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"^0\.([0-3]([^0-9]|$)|4([^0-9.]|$)|4\.0)", string:version) ) security_hole(port);

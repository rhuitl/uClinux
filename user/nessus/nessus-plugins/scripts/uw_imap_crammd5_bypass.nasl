#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16272);
 script_cve_id("CVE-2005-0198");
 script_bugtraq_id(12391);
 script_version ("$Revision: 1.3 $");
  
 name["english"] = "UW-IMAP CRAM-MD5 Remote Authentication Bypass Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the remote UW-IMAP server which allows an
authenticated user to log into the server as any user.  The flaw is
in the CRAM-MD5 authentication theme. 

An attacker, exploiting this flaw, would only need to identify a
vulnerable UW-IMAP server which had enabled the CRAM-MD5 authentication
scheme.  
The attacker would then be able to log in as any valid user.

It is important to note that the IMAP daemon will automatically enable
CRAM-MD5 if the /etc/cram-md5.pwd file exists.


Solution : Upgrade to the most recent version of UW-IMAP.
           In addition, the fact that CRAM-MD5 is enabled indicates that
           the server is storing the IMAP passwords in plaintext.
           Ensure that the /etc/cram-md5.pwd file is mode 0400.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of UW-IMAP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Misc.");

 script_dependencie("find_service.nes", "find_service2.nasl");	       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port) port = 143;

key = string("imap/banner/", port);
banner = get_kb_item(key);
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    { 
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}
if(!banner) exit(0);

if (("IMAP4rev1" >< banner) && ("AUTH=CRAM-MD5"  >< banner))
{
  if(egrep (pattern:"^\* OK \[CAPABILITY IMAP4REV1 .*AUTH=CRAM-MD5.*\] .*IMAP4rev1 (200[1-3]\..*|2004\.([0-2]|3([0-4]|5[0-2])))", string:banner))
  {
    security_hole(port);
  }    
} 

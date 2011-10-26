#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") || ! defined_func("unixtime") ) exit(0);

if(description)
{
 script_id(11574);
 script_bugtraq_id(7342, 7467, 7482, 11781);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0190");

 
 
 name["english"] = "Portable OpenSSH PAM timing attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seem to be  running an SSH server which can allow
an attacker to determine the existence of a given login by comparing
the time the remote sshd daemon takes to refuse a bad password for a 
non-existent login compared to the time it takes to refuse a bad password
for a valid login.

An attacker may use this flaw to set up  a brute force attack against
the remote host.

Solution : Disable PAM support if you do not use it, upgrade to the newest 
version of OpenSSH

Risk factor : Low";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the timing of the remote SSH server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";

 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


include("ssh_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

if ( thorough_tests ) 
  if ( "openssh" >!<  tolower(banner) ) exit(0);



soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

then = unixtime();
ret = ssh_login(socket:soc, login:"nonexistent" + rand(), password:"n3ssus");
now = unixtime();
close(soc);

inval_diff = now - then;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
then = unixtime();
ret = ssh_login(socket:soc, login:"bin", password:"n3ssus");
now = unixtime();
val_diff = now - then;
if ( ( val_diff - inval_diff ) >= 2 ) security_note(port);


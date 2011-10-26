#TRUSTED 4219fe6f12ad8e1b320454e8599df69550da9644252b4e788bb53a7c6c0b5a71d82ee85664198903f0e0b7ef81bdd93c29efeb805d3cf43f64ad70edfd8d93e77bc070dcfe4b6d5899cf44cd170f354e29cf71bfadbb622314e404511b50e4942331fc3520248a8b29d3cc8c6a87b059e3cb101df07f463b1e66127579cb46200923d36caf92b4a1ad0a1519ba8f602a940785788ff8c87803e426865f9d205da2af9d713d3c9b931fd45df73d514613c005a237cb95ce04669e9d97f9ef0174e01a4d07bde384406086715dd0923877e343d147256e2c19b4065a182f01700c3b15ea39020a61ff363b53bcdd49e6a60495e8d2e823cb4c3405705564035d4c42f8524f8e61100981e3c1279b81dd41524821d57d6c354a2bf12b9ad31e91c646ee62fa12e2283fe9ce1356b95577db69a2051cb7e2453c6238807a819fd5b95c03bf49174c6f60c340c87ba56d2a52bd4cd7527e2ec2d5426a58ea52c12698d9f4ccdc1d1d6ad78af66e21bb285a354d54538f122038fec065f8cc9623fb0b36cd69785cae2c2092220fc999ff4d3b2daf4c2a62de74c1b9bb2a82d921fc62f2856fa003a79319d768f79684fba46b8d90cae927532b67ae3dd79b003cd637d58b2ed0d8260f270ad1a556f203e1101d06a4f259835fa54eb24f3cb64a7632d1273688999c63e2eea894e58fe28487aef6d7dcf9ffed81f5f65ab9a6f28cbb
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16151);
 script_version ("1.1");
 script_bugtraq_id(12238);
 script_cve_id("CAN-2005-0043");
 name["english"] = "iTunes < 4.7.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of iTunes which is older than
version 4.7.1.

The remote version of this software is vulnerable to a buffer overflow
when it parses a malformed playlist file (.m3u or .pls files).

Solution : Upgrade to iTunes 4.7.1
See also : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check the version of iTunes";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("ssh_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

cmd = 'cd /Applications/ && osascript -e \'tell application "Finder" to get {version} of alias "::iTunes.app"\'';

if ( islocalhost() )
{
 buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
}
else 
{
 sock = ssh_login_or_reuse_connection();
 if ( ! sock ) exit(0);
 buf = ssh_cmd(socket:sock, cmd:cmd);
 ssh_close_connection();
}

if ( ! buf ) exit(0);
if ( ! ereg(pattern:"^iTunes [0-9.]", string:buf) ) exit(0);
version = ereg_replace(pattern:"^iTunes ([0-9.]+),.*", string:buf, replace:"\1");
set_kb_item(name:"iTunes/Version", value:version);
if ( egrep(pattern:"iTunes 4\.([0-6]\..*|7|7\.0)$", string:buf) ) security_hole(port); 

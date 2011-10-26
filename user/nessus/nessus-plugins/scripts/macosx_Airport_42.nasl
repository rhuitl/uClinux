#TRUSTED 4e1fd1d002c8d302bfb935d56fd1d9c0a9fd9b7d9d70a3e1f1d6c459673ade57e108a217a6daca715ff8ba3f873c5c60d3b6f276c8e0d5c3bb389b89d5a999f397812db0368044ab3a32bea37354a8dbbc401a958b72588e1bf4ad8ce9c943a56fe30c246c49aefa05bdc32e7798c39f49b47ccdf60549fc501747d7cf2bc06c3ad73766718b3bcd2326c8984cfec0606af9d3f63f207144df9cefcafa6460cae3b19e43f352970577c963a74f0de372a24e2acd582d7c30858b0b98636a0e3cf5f96e6804b23569cb00378ac3b4caa2699faaf47c1edd62868235cd32333acbb83401ef5e2025b3319fd81b94c880455e7a24432d31cec9fe55bf82315c07520faae36c2ead43ddc97b15f211e86d18c03a904afb1191c8a0b5153f584b2f4125db6585170ec24ef14027aad01faa31e0e604f46f8fcc38d92ff04b16b93689b26a1b0af1d7aa0a30ca3c90d7b207a9fae57cc3fbb6be5fe2d8ea2ee4700253c3aad97cb722e3d889392c71df7e47093c9892aab08953470bd8454e4040182a493cbb5b08747784566f17473b8ccb32e02d1378dc09a4e033874e14aac99a096f2605c8d936687b202060553d25f7cd7f3be6823faac78f1f955de02e3d095a834d15f229655bf4275ce7231690f6250913be51920956e007bea5ea025b5f29ff07bf31aa598da56d3443f89ffab86bac54e7610e873cf06e85c24c1957a0ff
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19295);
 script_version ("1.0");
 script_bugtraq_id(14321);
 script_cve_id("CAN-2005-2196");
 name["english"] = "Airport < 4.2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Mac OS X which contains an Airport 
driver which is vulnerable to an automatic network association vulnerability, 
which may cause a computer to connect to potentially malicious networks without
notifying the end-user.

Solution : Upgrade to Airport 4.2
See also : http://docs.info.apple.com/article.html?artnum=301988
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of Mac OS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("Host/OS/icmp");
if ( ! os ) exit(0);

if ( !ereg(pattern:"Mac OS X 10\.(3|4\.[012]([^0-9]|$))", string:os) ) exit(0);

if ( islocalhost() )
{
 buf = pread(cmd:"grep", argv:make_list("grep", "string.[0-9]\.[0-9]", "/Library/Receipts/AirPortConfigApps.pkg/Contents/version.plist"));
}
else 
{
 sock = ssh_login_or_reuse_connection();
 if ( ! sock ) exit(0);
 buf = ssh_cmd(socket:sock, cmd:"grep 'string.[0-9]\.[0-9]' /Library/Receipts/AirPortConfigApps.pkg/Contents/version.plist");
 ssh_close_connection();
}


if ( buf && ereg(pattern:"<string>([0-3]\.|4\.[01](\..*)?)</string>", string:buf) ) security_hole(port);

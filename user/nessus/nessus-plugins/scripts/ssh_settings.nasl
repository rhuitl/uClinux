#TRUSTED 06471278d8e7915ccdb19774ab8f5c13863ecadcd78ed6df479a5b4e465499f8fe5081a40434d79edb3ff2a99c3832e0bb139f0c26b8dd56bbc13f287f2ae92a65a7ce62c669e6abb218e704d64ec10c239b780bb76c3c7bbb5d6870ec3f4b3cb0957ce909aa9c90c3963c95c807ccb8bd8dda6bbcc9dc0e9a3c7c6166b848ef9a5e32706be4309be389cd755e826b406bd960fa2494d32fd741710e048ac67469902727ffae16cec5f6fefb8f2d6bebc104fe022b560bee2e278cfc14a576e91590829332a2fb9b112a36d748e590a89bcccdea7086426badc2c39a03a2657aafd284e814f341e305c16e382c4ac782d1df13daca09685c909783bc4e01ff410c58c392a5844dad5569828c12aefa87652aa66d88c74075d0664126fd0e8cf7eb8d25da172aa191b07ab3f61eeb163b6f695804ac2ef4bbb9c1c17b9c0f2ed325d034e7409c9d2060474af9c3d510f4e89827c27989fb31b560aba88f8462244cf8d4c2a05cbca877de0e3f4a9af6aac637e59478f2b2d3ac187b5fdeb2aa24b5924b775505b41c6619d96fc4aa89cd0b72f1449a0eb906cb75244e2e2b7ad2d17e179e780095d96d34b4fb1ed4e9ba3ebfd488907ccdcc68a7e746d1b2bd7a76a6225f33f9f737558d6449062af59be5f921294ae7bf9e249a94735e803e42fde58e6fd4e17ca243fa05d4ed6e2c9f8f049171ab6dfedeb864fa937ab2ebf9
#
# This script was extract by Michel Arboi from 
# ssh_get_info which is (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14273);
 script_version ("1.9");
 name["english"] = "SSH settings";
 desc["english"] = "
This script just sets global variables (SSH keys, user name, passphrase)
and does not perform any security check

Risk factor: None";
 script_description(english:name["english"]);
 script_name(english:name["english"]);
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "set SSH keys & user name to perform local security checks";
 script_summary(english:summary["english"]);
 script_copyright(english:"Copyright (C) 2004 Michel Arboi");
 script_category(ACT_INIT);
 if (defined_func("bn_random"))
 {
   script_add_preference(name:"SSH user name : ",
                       type:"entry",
                       value:"root");
   script_add_preference(name:"SSH password (unsafe!) : ",
                       type:"password",
                       value:"");
   script_add_preference(name:"SSH public key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"SSH private key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Passphrase for SSH key : ",
                       type:"password",
                       value:"");
 }

 exit(0);
}

account     = script_get_preference("SSH user name : ");
password    = script_get_preference("SSH password (unsafe!) : ");
public_key  = script_get_preference_file_content("SSH public key to use : ");
private_key = script_get_preference_file_content("SSH private key to use : ");
passphrase  = script_get_preference("Passphrase for SSH key : ");

set_kb_item(name:"Secret/SSH/login", value:account);
if (password) set_kb_item(name:"Secret/SSH/password", value:password);
if (public_key) set_kb_item(name:"Secret/SSH/publickey", value:public_key);
if (private_key) set_kb_item(name:"Secret/SSH/privatekey", value:private_key);
if (passphrase) set_kb_item(name:"Secret/SSH/passphrase", value:passphrase);

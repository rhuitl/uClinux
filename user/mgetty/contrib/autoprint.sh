From owner-mgetty Tue May  7 22:46:47 1996
Return-Path: <owner-mgetty>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0uGteh-000053C@greenie.muc.de>; Tue, 7 May 96 22:46 MEST
Return-Path: <l-mgetty-owner@muc.de>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0uGteV-0006mLC@greenie.muc.de>; Tue, 7 May 96 22:46 MEST
Received: from mail2.dircon.co.uk ([194.112.32.10]) by vogon.muc.de with SMTP id <93325-3>; Tue, 7 May 1996 22:45:49 +0200
Received: from diversity.org.uk (diversity.org.uk [193.128.226.199]) by mail2.dircon.co.uk (8.7.5/8.7.3) with SMTP id VAA19338 for <mgetty@muc.de>; Tue, 7 May 1996 21:38:39 +0100 (BST)
From: Nigel Whitfield <nigel@diversity.org.uk>
Date: Tue, 7 May 1996 22:16:29 +0200
Reply-To: nigel@diversity.org.uk
X-Mailer: Mail User's Shell (7.2.5 10/14/92)
To: mgetty@muc.de
Subject: Some quick and dirty scripts
Message-ID: <9605072116.aa15322@fags.stonewall.demon.co.uk>
Status: ROr

Just in case anyone wants. here are a couple of very quick and
very dirty scripts that I use in conjunction with my mail
programs here. The end result is that from within elm or mush
using the print command prints ordinary messages, but for
notifications of incoming faxes, prints the fax instead.

Enjoy!

---- /usr/local/bin/autoprint - works out if this is a fax or not
#!/bin/sh -
#
# autoprint - attempts to determine if a mail message
# is a fax notification, and prints the fax if so,
# otherwise prints the mail message
#

# first save the text
cat - > /usr/tmp/autoprint.$$

if  grep -l -s 'Subject: fax from' /usr/tmp/autoprint.$$ 
then
	cat /usr/tmp/autoprint.$$ | /usr/local/bin/pfax 
else
	lp /usr/tmp/autoprint.$$
fi

rm -f /usr/tmp/autoprint.$$
---- end of autoprint

---- /usr/local/bin/pfax - prints the fax files named in the msg
#!/bin/sh -
#
# pfax - script to accept a fax notification message
# on std in and print it out
#
PAGES=`grep "fax/incoming"`
G3TOLJ="/usr/local/bin/g3tolj"

for i in $PAGES
do
	FAX=$i
	RES=`basename $FAX | sed 's/.\(.\).*/\1/'`

	if [ "$RES" = "n" ]
	then
		STRETCH="-aspect 2.0"
	else
		STRETCH=""
	fi

	$G3TOLJ $STRETCH $FAX \
	| lp -dlaser -oraw -onb > /dev/null

done

exit 0
---- end of pfax

Amend as necessary for your printer; this works for me on SCO ODT
3.

Nigel.

-- 
Nigel Whitfield                                     
nigel@diversity.org.uk                                      Digital Diversity
nigel@stonewall.demon.co.uk                                      and uk-motss
*****     All demon.co.uk sites are independently run internet hosts    *****


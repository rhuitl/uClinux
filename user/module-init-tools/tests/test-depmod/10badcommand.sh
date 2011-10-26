#! /bin/sh

# Test bad option handling.
for ENDIAN in -le -be; do
for BITNESS in 32 64; do

[ "`depmod --unknown 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

[ "`depmod -v --unknown 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]
[ "`depmod --unknown -v 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

[ "`depmod 2.6.0 --unknown 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]
[ "`depmod --unknown 2.6.0 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

[ "`depmod -v 2.6.0 --unknown 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]
[ "`depmod -v --unknown 2.6.0 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

[ "`depmod 2.6.0 -v --unknown 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]
[ "`depmod --unknown -v 2.6.0 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

[ "`depmod 2.6.0 --unknown -v 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]
[ "`depmod --unknown 2.6.0 -v 2>&1 | head -1`" = "depmod: malformed/unrecognized option '--unknown'" ]

done
done

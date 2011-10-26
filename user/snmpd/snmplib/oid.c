

#include		"ctypes.h"
#include		"debug.h"
#include		"rdx.h"
#include		"oid.h"

CIntfType		oidDecode (CCharPtrType result, CIntfType m, CBytePtrType oid, CIntfType n)
{
	CUnslType		val;
	CUnslType		quo;
	CByteType		c;
	CIntfType		k;
	CIntfType		s;

	s = m;
	val = (CUnslType) 0;

	do {
		c = *oid++;
		val = (val << 7) | (CUnslType) (c & (CByteType) 0x7F);
		n--;

	} while (((c & (CByteType) 0x80) != (CByteType) 0) &&
		(n != (CIntfType) 0));

	quo = val / (CUnslType) 40;
	k = rdxEncode10 (result, s, quo);
	if (k < (CIntfType) 0) {
		return (k);
	}
	result += k;
	s -= k;
	*result++ = (CCharType) '.';
	s--;
	k = rdxEncode10 (result, s, val - ((CUnslType) 40 * quo));
	result += k;
	s -= k;

	while ((n != (CIntfType) 0) && (k >= (CIntfType) 0)) {
		val = (CUnslType) 0;
		do {
			c = *oid++;
			val = (val << 7) | (CUnslType) (c & (CByteType) 0x7F);
			n--;

		} while (((c & (CByteType) 0x80) != (CByteType) 0) &&
			(n != (CIntfType) 0));

		*result++ = (CCharType) '.';
		s--;
		k = rdxEncode10 (result, s, val);
		result += k;
		s -= k;
	}

	*result = (CCharType) 0;
	return ((k < (CIntfType) 0) ? k : m - s);
}


static	CIntfType	oidEncodeSubid (CBytePtrType oid, CIntfType n, CUnslType val)
{
	CIntfType		k;
	CByteType		buf [ (2 * sizeof (val)) ];
	CBytePtrType		bp;
	CByteType		mask;

	k = (CIntfType) 0;
	mask = (CByteType) 0;
	bp = buf + sizeof (val) + sizeof (val);
	do {
		bp--;
		*bp = (CByteType) (val & (CUnslType) 0x7F) | mask;
		mask = (CByteType) 0x80;
		val >>= 7;
		k++;

	} while (val != (CUnslType) 0);

	if (k < n) {
		n = k;
		while (k-- != 0) {
			*oid++ = *bp++;
		}
	}

	return (n);
}

CIntfType		oidEncode (CBytePtrType oid, CIntfType n, CCharPtrType text)
{
	CUnslType		val;
	CUnslType		val1;
	CIntfType		state;
	CIntfType		h;
	CIntfType		k;
	CCharType		c;
	CBoolType		done;

	/*	Handle zero-length OID here	*/
	if ((*text == (CCharType) 0) && (n > (CIntfType) 0)) {
		return ((CIntfType) 0);
	}

	state = (CIntfType) 0;
	h = (CIntfType) 0;
	val = (CUnslType) 0;
	done = FALSE;

	while ((! done) && (n > (CIntfType) 0)) {
		c = *text++;
		if ((c >= (CCharType) '0') && (c <= (CCharType) '9')) {
			val = ((CUnslType) 10 * val) + (CUnslType)
				(c - (CCharType) '0');
		}
		else if (c == (CCharType) '.') {
			switch (state) {

			case 0:
				val1 = ((CUnslType) 40 * val);
				val = (CUnslType) 0;
				state = (CIntfType) 1;
				break;

			case 1:
				if (val > (CUnslType) 39) {
					n = (CIntfType) 0;
					done = TRUE;
					break;
				}
				else {
					val += val1;
					/*	fall through	*/
				}

			case 2:
				k = oidEncodeSubid (oid, n, val);
				h += k;
				n -= k;
				oid += k;
				val = (CUnslType) 0;
				state = (CIntfType) 2;
				break;
			}
		}
		else if (c == (CCharType) 0) {
			done = TRUE;
			switch (state) {

			case 0:
				n = (CIntfType) 0;
				break;

			case 1:
				if (val > (CUnslType) 39) {
					n = (CIntfType) 0;
					break;
				}
				else {
					val += val1;
					/*	fall through	*/
				}

			case 2:
				k = oidEncodeSubid (oid, n, val);
				h += k;
				n -= k;
				break;
			}
		}
		else {
			n = (CIntfType) 0;
			done = TRUE;
		}
	}

	return ((n > (CIntfType) 0) ? h : (CIntfType) -1);
}


#include	"ctypes.h"
#include	"debug.h"
#include	"local.h"
#include	"avl.h"

#define		avlDirOpposite(x)	\
		(((x) == avlDirLeft) ? avlDirRight : avlDirLeft)

typedef		struct			AvlTag {

		AvlInfoType		avlInfo;
		AvlBalanceType		avlBal;
		AvlIdType		avlRefs [ 3 ];

		}			AvlType;

typedef		AvlType			*AvlPtrType;

#define		avlIdToPtr(x)		((AvlPtrType) ((AvlIdType) (x)))
#define		avlPtrToId(x)		((AvlIdType) ((AvlPtrType) (x)))

#define		avlLinkGet(p, c)	((avlIdToPtr (p))->avlRefs \
						[ (int) (c) ])

#define		avlLinkSet(p, c, q)	(((avlIdToPtr (p))->avlRefs \
						[ (int) (c) ]) = (q))

#define		avlLeftGet(p)		((avlIdToPtr (p))->avlRefs \
						[ (int) avlDirLeft ])
#define		avlLeftSet(p, q)	(((avlIdToPtr (p))->avlRefs \
						[ (int) avlDirLeft ]) = (q))

#define		avlRightGet(p)		((avlIdToPtr (p))->avlRefs \
						[ (int) avlDirRight ])
#define		avlRightSet(p, q)	(((avlIdToPtr (p))->avlRefs \
						[ (int) avlDirRight ]) = (q))

#define		avlBalGet(p)		((avlIdToPtr (p))->avlBal)
#define		avlBalSet(p, c)		(((avlIdToPtr (p))->avlBal) = (c))

#define		avlInfoGet(p)		((avlIdToPtr (p))->avlInfo)
#define		avlInfoSet(p, w)	(((avlIdToPtr (p))->avlInfo) = (w))

#define		avlCmpFnGet(p)		((AvlCmpFnType) avlInfoGet ((p)))
#define		avlCmpFnSet(p, f)	(avlInfoSet ((p), (AvlInfoType) (f)))

#define		avlPrintFnGet(p)	((AvlPrintFnType)	\
					avlLinkGet ((p), avlDirBalanced))
#define		avlPrintFnSet(p, f)	((AvlPrintFnType)	\
					avlLinkSet ((p),	\
					avlDirBalanced, (AvlIdType) (f)))

typedef		struct			AvlStepTag {

		AvlIdType		avlStepNode;
		AvlBalanceType		avlStepDir;

		}			AvlStepType;

#define		avlPathSize		(512)

typedef		CUnsfType		AvlLevelType;

typedef		struct			AvlPathTag {

		AvlLevelType		avlPathLevel;
		AvlStepType		avlPathSteps [ 1 ];

		}			AvlPathType;

typedef		AvlPathType		*AvlPathPtrType;

typedef		CUnswType		AvlPathIdType;

#define		avlPathIdToPtr(p)	\
			((AvlPathPtrType) ((AvlPathIdType) (p)))

#define		avlPathPtrToId(p)	\
			((AvlPathIdType) ((AvlPathPtrType) (p)))

#define		avlPathNew(cp, n)	\
			((((AvlPathPtrType) cp)->avlPathLevel = 0),	\
			(avlPathPtrToId (cp)))

#define		avlPathDirGet(p, j) \
			((avlPathIdToPtr (p))->avlPathSteps[ (j) ].avlStepDir)

#define		avlPathDirSet(p, j, d) \
			((avlPathIdToPtr (p))->avlPathSteps[ (j) ].avlStepDir \
			= (d))

#define		avlPathNodeGet(p, j) \
			((avlPathIdToPtr (p))->avlPathSteps[ (j) ].avlStepNode)

#define		avlPathNodeSet(p, j, d) \
			((avlPathIdToPtr (p))->avlPathSteps[ (j) ].avlStepNode \
			= (d))

#define		avlPathLevelGet(p) \
			((avlPathIdToPtr (p))->avlPathLevel)

#define		avlPathLevelSet(p, d) \
			((avlPathIdToPtr (p))->avlPathLevel = (d))


#ifdef		DEBUG

static	AvlStatusType	avlPrintNode (p, printFn)

AvlIdType		p;
AvlPrintFnType		printFn;

{
	printf ("(");
	if (p != (AvlIdType) 0) {
		(void) avlPrintNode (avlLeftGet (p), printFn);
		printf ("[%d]", avlBalGet (p));
		(*printFn) (avlInfoGet (p));
		(void) avlPrintNode (avlRightGet (p), printFn);
	}
	printf (")");
	return (errOk);
}

static	AvlStatusType	avlPrint (p)

AvlIdType		p;

{
	if (p != (AvlIdType) 0) {
		if (avlPrintFnGet (p) != (AvlPrintFnType) 0) {
			(void) avlPrintNode (avlRightGet (p),
				avlPrintFnGet (p));
		}
	}
	else {
		printf ("NIL");
	}
	return (errOk);
}

static	CIntfType	avlVerifyNode (p)

AvlIdType		p;

{
	CIntfType		l;
	CIntfType		r;
	CIntfType		d;
	CIntfType		result;
	AvlBalanceType		c;
	AvlBalanceType		e;

	if (p == (AvlIdType) 0) {
		return ((CIntfType) 0);
	}

	l = avlVerifyNode (avlLeftGet (p));
	r = avlVerifyNode (avlRightGet (p));
	c = avlBalGet (p);
	if (l > r) {
		result = l;
		d = l - r;
		e = avlDirLeft;
	}
	else if (l < r) {
		result = r;
		d = r - l;
		e = avlDirRight;
	}
	else {
		result = r;
		d = 0;
		e = avlDirBalanced;
	}
	result++;

	if ((d > 1) || (c != e)) {
		printf ("avlVerify: Node %08.08X bad\n", p);
	}
	return (result);
}

static	CIntfType	avlVerify (p)

AvlIdType		p;

{
	CIntfType		r;

	if (p != (AvlIdType) 0) {
		r = avlVerifyNode (avlRightGet (p));
	}
	else {
		r = (CIntfType) 0;
	}
	return (r);
}

static	CVoidType	avlPathPrint (path)

AvlPathIdType		path;

{
	AvlLevelType		level;
	AvlLevelType		i;

	if (path != (AvlPathIdType) 0) {
		level = avlPathLevelGet (path);
		printf ("avlPathPrint: level %d\n", level);
		for (i = 1; i <= level; i++) {
			printf ("%08.08.X %d\n", avlPathNodeGet (path, i),
				avlPathDirGet (path, i));
		}
	}
}

#define		DEBUGAVLPATH(p)		avlPathPrint ((p))
#define		DEBUGAVLVERIFY(p)	(void) avlVerify ((p))
#define		DEBUGAVLTREE(p)		(void) avlPrint ((p))

#else		/*	DEBUG	*/

#define		DEBUGAVLPATH(p)
#define		DEBUGAVLVERIFY(p)
#define		DEBUGAVLTREE(p)

#endif		/*	DEBUG	*/

CVoidType		avlInit (void)
{
	DEBUGAVLPATH ((AvlPathIdType) 0);
	DEBUGAVLVERIFY ((AvlIdType) 0);
	DEBUGAVLTREE ((AvlIdType) 0);
}

static	AvlIdType	avlFreeNode (AvlIdType p)
{
	if (p != (AvlIdType) 0) {
		(void) free ((char *) avlIdToPtr (p));
	}
	return ((AvlIdType) 0);
}

AvlIdType		avlFree (AvlIdType p)
{
	if (p != (AvlIdType) 0) {
		(void) avlFree (avlLeftGet (p));
		(void) avlFree (avlRightGet (p));
	}

	return (avlFreeNode (p));
}

static	AvlIdType	avlAllocNode (void)
{
	AvlPtrType		p;

	p = (AvlPtrType) malloc ((unsigned) sizeof (*p));
	if (p != (AvlPtrType) 0) {
		(void) bzero ((char *) p, (int) sizeof (*p));
	}
	return (avlPtrToId (p));
}

AvlIdType		avlNew (AvlCmpFnType cmpFn, AvlPrintFnType printFn)
{
	AvlIdType		p;

	if ((p = avlAllocNode ()) != (AvlIdType) 0) {
		(void) avlCmpFnSet (p, cmpFn);
		(void) avlRightSet (p, (AvlIdType) 0);
		(void) avlLeftSet (p, (AvlIdType) printFn);
		(void) avlBalSet (p, avlDirBalanced);
	}
	return (p);
}


static	AvlIdType	avlChangeHead (AvlIdType root, AvlLevelType j, AvlPathIdType path)
{
	AvlLevelType		level;

	level = avlPathLevelGet (path);
	if (level == 1) {
		root = avlPathNodeGet (path, j);
	}
	else {
		level--;
		(void) avlLinkSet (avlPathNodeGet (path, level),
			avlPathDirGet (path, level),
			avlPathNodeGet (path, j));
	}
	return (root);
}

#ifdef		INLINE

#define		avlExchange(path, a, b)	\
	(void) avlLinkSet (avlPathNodeGet ((path), (a)),	\
		avlPathDirGet ((path), (a)),	\
		avlLinkGet (avlPathNodeGet ((path), (b)),	\
		avlDirOpposite (avlPathDirGet ((path), (a)))));	\
	(void) avlLinkSet (avlPathNodeGet ((path), (b)),	\
		avlDirOpposite (avlPathDirGet ((path), (a))),	\
		avlPathNodeGet ((path), (a)));

#else		/*	INLINE	*/

static	CVoidType	avlExchange (AvlPathIdType path, AvlLevelType a, AvlLevelType b)
{
	(void) avlLinkSet (avlPathNodeGet (path, a),
		avlPathDirGet (path, a),
		avlLinkGet (avlPathNodeGet (path, b),
		avlDirOpposite (avlPathDirGet (path, a))));
	(void) avlLinkSet (avlPathNodeGet (path, b),
		avlDirOpposite (avlPathDirGet (path, a)),
		avlPathNodeGet (path, a));
}

#endif		/*	INLINE	*/

#ifdef		INLINE

#define		avlSavePath(path, place, dir)	\
		{	\
			AvlLevelType	level;	\
			level = avlPathLevelGet ((path)) + 1;	\
			(void) avlPathLevelSet ((path), level);	\
			(void) avlPathNodeSet ((path), level, (place));	\
			(void) avlPathDirSet ((path), level, (dir));	\
		}

#else		/*	INLINE	*/

static	CVoidType	avlSavePath (AvlPathIdType path, AvlIdType place, AvlBalanceType dir)
{
	AvlLevelType		level;

	level = avlPathLevelGet (path) + 1;
	(void) avlPathLevelSet (path, level);
	(void) avlPathNodeSet (path, level, place);
	(void) avlPathDirSet (path, level, dir);
}

#endif		/*	INLINE	*/

static	AvlIdType	avlSearchNode (AvlIdType root, AvlNamePtrType name, AvlLengthType namelen, AvlPathIdType path, AvlCmpFnType cmpFn)
{
	AvlIdType		where;
	AvlBalanceType		dir;
	CBoolType		notfound;

	where = root;
	notfound = TRUE;

	while ((where != (AvlIdType) 0) && (notfound)) {
		dir = (*cmpFn) (avlInfoGet (where), name, namelen);
		if (dir == avlDirBalanced) {
			notfound = FALSE;
		}
		else {
			avlSavePath (path, where, dir);
			where = avlLinkGet (where, dir);
		}
	}

	return (where);
}

AvlInfoType		avlFind (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen)
{
	AvlIdType		where;
	AvlIdType		root;
	AvlPathIdType		path;
	CByteType		pathArea [ avlPathSize ];

	if (head == (AvlIdType) 0) {
		return ((AvlInfoType) 0);
	}

	root = avlRightGet (head);

	path = avlPathNew (pathArea, avlPathSize);
	if (path == (AvlPathIdType) 0) {
		return ((AvlInfoType) 0);
	}

	where = avlSearchNode (root, name, namelen, path, avlCmpFnGet (head));
	if (where == (AvlIdType) 0) {
		return ((AvlInfoType) 0);
	}

	return (avlInfoGet (where));
}

static	AvlIdType	avlCessorNode (AvlIdType p, AvlPathIdType path)
{
	AvlLevelType		level;
	AvlIdType		n;

	if ((p == (AvlIdType) 0) || ((n = avlRightGet (p)) ==
		(AvlIdType) 0)) {
		for (level = avlPathLevelGet (path); ((level != 0) &&
			(avlPathDirGet (path, level) == avlDirRight));
			level--);
		if (level == 0) {
			(void) avlPathLevelSet (path, level);
			return ((AvlIdType) 0);
		}
		else {
			p = avlPathNodeGet (path, level);
			(void) avlPathLevelSet (path, level - 1);
			return (p);
		}
	}
	else {
		avlSavePath (path, p, avlDirRight);
		p = n;
		while ((n = avlLeftGet (p)) != (AvlIdType) 0) {
			avlSavePath (path, p, avlDirLeft);
			p = n;
		}
		return (p);
	}
}

AvlInfoType		avlCessor (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen)
{
	AvlIdType		where;
	AvlPathIdType		path;
	CByteType		pathArea [ avlPathSize ];

	if (head == (AvlIdType) 0) {
		return ((AvlInfoType) 0);
	}

	path = avlPathNew (pathArea, avlPathSize);
	if (path == (AvlPathIdType) 0) {
		return ((AvlInfoType) 0);
	}

	where = avlSearchNode (avlRightGet (head), name, namelen,
		path, avlCmpFnGet (head));
	where = avlCessorNode (where, path);
	if (where == (AvlIdType) 0) {
		return ((AvlInfoType) 0);
	}

	return (avlInfoGet (where));
}

static	AvlIdType	avlCriticalNode (AvlIdType root, AvlPathIdType path, AvlLevelType level)
{
	(void) avlPathLevelSet (path, level);
	if (avlPathDirGet (path, level) ==
		avlPathDirGet (path, level + 1)) {
		root = avlChangeHead (root, level + 1, path);
		avlExchange (path, level, level + 1);
		(void) avlBalSet (avlPathNodeGet (path, level),
			avlDirBalanced);
		(void) avlBalSet (avlPathNodeGet (path, level + 1),
			avlDirBalanced);
	}
	else {
		root = avlChangeHead (root, level + 2, path);
		avlExchange (path, level, level + 2);
		avlExchange (path, level + 1, level + 2);
		(void) avlBalSet (avlPathNodeGet (path, level + 2),
			avlDirBalanced);
		if (avlPathDirGet (path, level + 1) ==
			avlPathDirGet (path, level + 2)) {
			(void) avlBalSet (avlPathNodeGet (path, level),
				avlDirBalanced);
			(void) avlBalSet (avlPathNodeGet (path,
				level + 1), avlDirOpposite (
				avlPathDirGet (path, level + 1)));
		}
		else if (avlPathDirGet (path, level + 2) !=
			avlDirBalanced) {
			(void) avlBalSet (avlPathNodeGet (path,
				level), avlDirOpposite (
				avlPathDirGet (path, level)));
			(void) avlBalSet (avlPathNodeGet (path,
				level + 1), avlDirBalanced);
			
		}
		else {
			(void) avlBalSet (avlPathNodeGet (path, level),
				avlDirBalanced);
			(void) avlBalSet (avlPathNodeGet (path,
				level + 1), avlDirBalanced);
		}
	}
	return (root);
}

AvlStatusType		avlInsert (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen, AvlInfoType info)
{
	CBoolType		notdone;
	AvlIdType		where;
	AvlIdType		root;
	AvlBalanceType		weight;
	AvlPathIdType		path;
	CByteType		pathArea [ avlPathSize ];
	AvlLevelType		level;
	AvlBalanceType		dir;
	AvlIdType		node;

	if (head == (AvlIdType) 0) {
		return (errBad);
	}

	if (info == (AvlInfoType) 0) {
		return (errBad);
	}

	root = avlRightGet (head);

	path = avlPathNew (pathArea, avlPathSize);
	if (path == (AvlPathIdType) 0) {
		return (errBad);
	}

	where = avlSearchNode (root, name, namelen, path, avlCmpFnGet (head));
	if (where != (AvlIdType) 0) {
		return (errBad);
	}

	where = avlAllocNode ();
	if (where == (AvlIdType) 0) {
		return (errBad);
	}
	(void) avlInfoSet (where, info);
	(void) avlLeftSet (where, (AvlIdType) 0);
	(void) avlRightSet (where, (AvlIdType) 0);
	(void) avlBalSet (where, avlDirBalanced);
	avlSavePath (path, where, avlDirBalanced);
	level = avlPathLevelGet (path);
	root = avlChangeHead (root, level, path);

	notdone = TRUE;

	for (level = level - 1; (level != 0) && (notdone); level--) {

		node = avlPathNodeGet (path, level);
		weight = avlBalGet (node);
		dir = avlPathDirGet (path, level);
		if (weight == dir) {
			root = avlCriticalNode (root, path, level);
			notdone = FALSE;
		}
		else {
			(void) avlBalSet (node, dir);
			if (weight != avlDirBalanced) {
				(void) avlBalSet (node, avlDirBalanced);
				notdone = FALSE;
			}
		}
	}

	(void) avlRightSet (head, root);
	DEBUGAVLVERIFY (root);
	DEBUGAVLTREE (root);
	DEBUG0 ("\n");
	return (errOk);
}

AvlStatusType		avlRemove (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen)
{
	CBoolType		notdone;
	AvlPathIdType		path;
	CByteType		pathArea [ avlPathSize ];
	AvlLevelType		level;
	AvlBalanceType		dir;
	AvlBalanceType		opp;
	AvlBalanceType		bal;
	AvlBalanceType		balb;
	AvlIdType		root;
	AvlIdType		a;
	AvlIdType		b;
	AvlIdType		x;
	AvlIdType		p;
	AvlIdType		q;
	AvlIdType		n;

	if (head == (AvlIdType) 0) {
		return (errBad);
	}

	path = avlPathNew (pathArea, avlPathSize);
	if (path == (AvlPathIdType) 0) {
		return (errBad);
	}

	root = avlRightGet (head);
	avlSavePath (path, head, avlDirRight);

	p = avlSearchNode (root, name, namelen, path, avlCmpFnGet (head));

	if (p == (AvlIdType) 0) {
		return (errBad);
	}

	q = p;

	avlSavePath (path, p, avlDirRight);
	if (avlRightGet (p) != (AvlIdType) 0) {
		q = avlRightGet (p);
		avlSavePath (path, q, avlDirLeft);
		while ((n = avlLeftGet (q)) != (AvlIdType) 0) {
			q = n;
			avlSavePath (path, q, avlDirLeft);
		}
	}

	(void) avlInfoSet (p, avlInfoGet (q));
	level = avlPathLevelGet (path);

	(void) avlLinkSet (
		avlPathNodeGet (path, level - 1),
		avlPathDirGet (path, level - 1),
		avlLinkGet (
			avlPathNodeGet (path, level),
			avlDirOpposite (avlPathDirGet (path, level))));

	(void) avlFreeNode (q);
	notdone = TRUE;

	for (level = level - 1; (level > 1) && (notdone); level--) {

		a = avlPathNodeGet (path, level);
		bal = avlBalGet (a);
		dir = avlPathDirGet (path, level);
		opp = avlDirOpposite (dir);
		b = avlLinkGet (a, opp);
		balb = avlBalGet (b);
		if (bal == dir) {
			(void) avlBalSet (a, avlDirBalanced);
		}
		else if (bal == avlDirBalanced) {
			(void) avlBalSet (a, opp);
			notdone = FALSE;
		}
		else if (balb == avlDirBalanced) {
			/* Rebalance: case 3 */
			(void) avlLinkSet (a, opp, avlLinkGet (b, dir));
			(void) avlLinkSet (b, dir, a);
			(void) avlBalSet (a, opp);
			(void) avlBalSet (b, dir);
			(void) avlLinkSet (avlPathNodeGet (path,
				level - 1), avlPathDirGet (path,
				level - 1), b);
			notdone = FALSE;
		}
		else if (balb == opp) {
			/* Rebalance: case 1 */
			(void) avlLinkSet (a, opp, avlLinkGet (b, dir));
			(void) avlLinkSet (b, dir, a);
			(void) avlBalSet (a, avlDirBalanced);
			(void) avlBalSet (b, avlDirBalanced);
			(void) avlLinkSet (avlPathNodeGet (path,
				level - 1), avlPathDirGet (path,
				level - 1), b);
		}
		else {
			/* Rebalance: case 2 */
			x = avlLinkGet (b, balb);
			(void) avlLinkSet (a, opp, avlLinkGet (x, dir));
			(void) avlLinkSet (b, dir, avlLinkGet (x, opp));
			(void) avlLinkSet (x, opp, b);
			(void) avlLinkSet (x, dir, a);
			if (avlBalGet (x) == avlDirBalanced) {
				(void) avlBalSet (a, avlDirBalanced);
				(void) avlBalSet (b, avlDirBalanced);
			}
			else if (avlBalGet (x) == opp) {
				(void) avlBalSet (a, dir);
				(void) avlBalSet (b, avlDirBalanced);
				(void) avlBalSet (x, avlDirBalanced);
			}
			else {
				(void) avlBalSet (b, opp);
				(void) avlBalSet (a, avlDirBalanced);
				(void) avlBalSet (x, avlDirBalanced);
			}
			(void) avlLinkSet (avlPathNodeGet (path,
				level - 1), avlPathDirGet (path,
				level - 1), x);
		}
	}

	root = avlRightGet (head);
	DEBUGAVLVERIFY (root);
	DEBUGAVLTREE (root);
	DEBUG0 ("\n");
	return (errOk);
}


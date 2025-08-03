/*
 * Copy me if you can.
 * by 20h
 */

#include <u.h>
#include <libc.h>
#include <ctype.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>
#include <ip.h>
#include <libsec.h>
#include <auth.h>
#include "scsireq.h"

#define PATH(type, n)		((type)|((n)<<8))
#define TYPE(path)			((int)(path) & 0xFF)
#define NUM(path)			((uint)(path)>>8)

enum {
	Qdir = 0,
	Qctl,
	Qn,
	Qraw,
	Qcctl,
	Qdata,

	CMreset = 1,

	Pcmd = 0,
	Pdata,
	Pstatus,

	Cnop = 0x00,
	Cscsi,
	Cmgmt,
	Clogin,
	Ctext,
	Cdataout,
	Clogout,

	Csnack = 0x10,

	Rnop = 0x00,
	Rscsi,
	Rmgmt,
	Rlogin,
	Rtext,
	Rdatain,
	Rlogout,

	Rr2t = 0x31,
	Rasync,

	Rreject = 0x3F,

	MaxPacketSize = 65536,
};

typedef struct Dirtab Dirtab;
struct Dirtab {
	char	*name;
	int		mode;
};
Dirtab dirtab[] = {
	".",	DMDIR|0555,
	"ctl",	0640,
	nil,	DMDIR|0640,
	"raw",	0640,
	"ctl",	0640,
	"data",	0640,
};

Cmdtab cmdtab[] = {
	CMreset,	"reset",	1,
};

typedef struct Iscsi Iscsi;
struct Iscsi {
	ScsiReq;
	ulong	blocks;
	vlong	capacity;
	uchar 	rawcmd[10];
	uchar	phase;
};

typedef struct Iscsis Iscsis;
struct Iscsis {
	Iscsi	lun[256];
	uchar	maxlun;
	int		fd;
};

Iscsis iscsi;
long starttime;
char *owner, *host, *vol;
int debug, tls;

typedef struct Ihdr Ihdr;
struct Ihdr {
	char op;
	char flags;
	char spec1;
	char spec2;
	char ahslen;
	char datalen[3];
	char lun[8];
	char itt[4];
	char ttt[4];
	char statsn[4];
	char expect[4];
	char max[4];
	char datasn[4];
	char offset[4];
	char rcount[4];
};

typedef struct Iscsipkt Iscsipkt;
struct Iscsipkt {
	char *buf;
	Ihdr *hdr;
	long len;
	char *data;
};

void
freepkt(Iscsipkt *pkt)
{
	if(pkt != nil) {
		if(pkt->buf != nil)
			free(pkt->buf);
		free(pkt);
	}
}

Iscsipkt *
mkpkt(int len)
{
	Iscsipkt *pkt;

	pkt = emalloc9p(sizeof(Iscsipkt));
	pkt->buf = emalloc9p(48 + len);
	pkt->hdr = (Ihdr *)pkt->buf;
	pkt->data = pkt->buf + 48;
	pkt->len = 0;

	return pkt;
}

Iscsipkt *
readpkt(int fd)
{
	Iscsipkt *pkt;
	char ahslen;
	long len;

	pkt = mkpkt(0);
	if(readn(fd, pkt->buf, 48) != 48)
		sysfatal("readn: %r");

	ahslen = pkt->hdr->ahslen;
	pkt->hdr->ahslen = 0x00;
	pkt->len = (long)nhgetl(&pkt->hdr->ahslen);
	pkt->hdr->ahslen = ahslen;

	if(pkt->len != 0) {
		len = pkt->len;
		if(pkt->len % 4 != 0)
			len += 4 - pkt->len % 4;
		if(debug)
			fprint(2, "added %ld %ld bytes to read\n", pkt->len, len);
		pkt->buf = erealloc9p(pkt->buf, 48 + len);
		pkt->hdr = (Ihdr *)pkt->buf;
		pkt->data = pkt->buf + 48;

		if(readn(fd, pkt->data, len) < 0)
			sysfatal("readn: %r");
	}

	return pkt;
}

char *
adddataparam(char *buf, char *name, char *val)
{
	strcpy(buf, name);
	buf += strlen(name);
	*buf++ = '=';
	strcpy(buf, val);
	buf += strlen(val);
	*buf++ = '\0';

	return buf;
}

int
iscsilogin(Iscsis *iscsi)
{
	Iscsipkt *pkt;
	char *attr;
	long len;

	pkt = mkpkt(MaxPacketSize - 48);

	memset(pkt->buf, 0, MaxPacketSize);
	pkt->hdr->op = Clogin | 0x40;
	pkt->hdr->flags = 0x87;
	pkt->hdr->lun[1] = 0x02;
	pkt->hdr->lun[2] = 0x3D;
	pkt->hdr->itt[1] = 0x0A;

	attr = pkt->data;
	attr = adddataparam(attr, "InitiatorName", "iqn.2006-05.de.9grid");
	attr = adddataparam(attr, "InitiatorAlias", "Plan 9");
	attr = adddataparam(attr, "TargetName", vol);
	attr = adddataparam(attr, "SessionType", "Normal");
	attr = adddataparam(attr, "HeaderDigest", "None");
	attr = adddataparam(attr, "DataDigest", "None");
	attr = adddataparam(attr, "DefaultTime2Wait", "0");
	attr = adddataparam(attr, "DefaultTime2Retain", "0");
	attr = adddataparam(attr, "IFMarker", "No");
	attr = adddataparam(attr, "OFMarker", "No");
	attr = adddataparam(attr, "ErrorRecoveryLevel", "0");
	attr = adddataparam(attr, "InitialR2T", "No");
	attr = adddataparam(attr, "ImmediateData", "Yes");
	attr = adddataparam(attr, "MaxBurstLength", "16776192");
	attr = adddataparam(attr, "FirstBurstLength", "262144");
	attr = adddataparam(attr, "MaxOutstandingR2T", "1");
	attr = adddataparam(attr, "MaxConnections", "1");
	attr = adddataparam(attr, "DataPDUInOrder", "Yes");
	attr = adddataparam(attr, "DataSequenceInOrder", "Yes");
	attr = adddataparam(attr, "MaxRecvDataSegmentLength", "131072");

	pkt->len = attr - pkt->data;
	hnputl(&pkt->hdr->ahslen, pkt->len);
	pkt->hdr->ahslen = 0x00;

	len = attr - pkt->buf;
	if(len % 4 != 0)
		len += 4 - len % 4;

	if(write(iscsi->fd, pkt->buf, len) != len)
		sysfatal("write: %r");
	freepkt(pkt);

	pkt = readpkt(iscsi->fd);
	if(pkt->hdr->datasn[0] != 0x00 || pkt->hdr->datasn[1] != 0x00)
		return 1;
	freepkt(pkt);

	return 0;
}	

int
iscsiconnect(Iscsis *iscsi)
{
	int fd;
	TLSconn *conn;
	AuthInfo *ai;

	iscsi->fd = dial(netmkaddr(host, "tcp", "3260"), 0, 0, 0);
	if(iscsi->fd < 0)
		sysfatal("dial: %r");

	if(tls){
		conn = mallocz(sizeof *conn, 1);
		ai = auth_proxy(iscsi->fd, auth_getkey, "proto=p9any role=client");
		if(ai == nil)
			sysfatal("auth_proxy: %r");
		conn->pskID = "p9secret";
		conn->psk = ai->secret;
		conn->psklen = ai->nsecret;
	
		fd = tlsClient(iscsi->fd, conn);
		if(fd < 0)
			sysfatal("tlsclient: %r");
		free(conn->sessionID);
		free(conn->cert);
		free(conn);
		free(ai);

		iscsi->fd = fd;
	}

	if(iscsilogin(iscsi))
		sysfatal("login failed");

	return 0;
}

int
iscsiinit(Iscsis *iscsi)
{
	uchar data[8], i;
	int maxlun;
	uchar luns[256*8+8];

	iscsi->maxlun = 0;
	iscsi->lun[0].iscsi = &iscsi->lun[0];
	iscsi->lun[0].flags = Fopen | Frw10;
	memset(luns, 0, sizeof(luns));

	/*
	* Some targets, like iscsisrv, don't have REPORT LUN. Pretend we only have lun
	* and hope for the best
	*/
	if((maxlun = SRreportlun(&iscsi->lun[0], (uchar *)luns, sizeof(luns))) < 0) {
		iscsi->maxlun = 1;
	} else 
		iscsi->maxlun = ((maxlun / 8) - 1) & 0xFF;


	if(debug)
		fprint(2, "maxlun: %.2ux\n", iscsi->maxlun);

	for(i = 0; i < (iscsi->maxlun & 0xFF); i++) {
		iscsi->lun[i].lun = luns[i*8 + 1];
		iscsi->lun[i].iscsi = &iscsi->lun[i];
		iscsi->lun[i].flags = Fopen | Frw10;
		if(SRinquiry(&iscsi->lun[i]) == -1)
			return -1;
		if(SRrcapacity(&iscsi->lun[i], data) == -1 && SRrcapacity(&iscsi->lun[i], data) == -1) {
			iscsi->lun[i].blocks = 0;
			iscsi->lun[i].capacity = 0;
			iscsi->lun[i].lbsize = 0;
		} else {
			iscsi->lun[i].lbsize = (data[4]<<28)|(data[5]<<16)|(data[6]<<8)|data[7];
			iscsi->lun[i].blocks = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
			iscsi->lun[i].blocks++;		// SRcapacity returns LBA of last block
			iscsi->lun[i].capacity = (vlong)iscsi->lun[i].blocks * iscsi->lun[i].lbsize;
		}
	}

	return 0;
}

void
iscsireset(Iscsis *iscsi)
{
	if(iscsiinit(iscsi) < 0) {
		iscsiconnect(iscsi);

		if(iscsiinit(iscsi) < 0)
			sysfatal("iscsireset failed");
	}
}

long
iscsirequest(Iscsi *lun, ScsiPtr *cmd, ScsiPtr *data, int *status)
{
	Iscsipkt *pkt, *rpkt;
	static int seq = -1;
	int n;
	long rcount;

	rcount = 0;

	pkt = mkpkt(MaxPacketSize - 48);
	memset(pkt->hdr, 0, sizeof(Ihdr));
	pkt->hdr->op = 0x01;

	pkt->hdr->flags = 0x81;
	if(data->count != 0) {
		if(data->write)
			pkt->hdr->flags |= 0x20;
		else
			pkt->hdr->flags |= 0x40;
	}

	memmove(pkt->hdr->lun, &lun->lun, 4);
	hnputl(pkt->hdr->itt, ++seq);
	hnputl(pkt->hdr->ttt, data->count);
	hnputl(pkt->hdr->statsn, seq);
	hnputl(pkt->hdr->expect, seq);

	memmove(pkt->hdr->max, cmd->p, cmd->count);
	memset(pkt->hdr->max + cmd->count, 0, 16 - cmd->count);
	if(data->write != 0) {
		memmove(pkt->data, data->p, data->count);
		pkt->len = data->count + data->count % 4;
		if(pkt->len != data->count)
			memset(pkt->data + data->count, 0, pkt->len - data->count);
	} else
		pkt->len = 0;
	hnputl(&pkt->hdr->ahslen, pkt->len);
	pkt->hdr->ahslen = 0x00;
	
	if(debug) {
		fprint(2, "cmd:");
		for (n = 0; n < 16; n++)
			fprint(2, " %.2ux", *(pkt->hdr->max + n) & 0xFF);
		fprint(2, " datalen: %ld\n", pkt->len);
	}

	if(write(iscsi.fd, pkt->buf, 48 + pkt->len) != pkt->len + 48)
		sysfatal("write: %r\n");

	rpkt = readpkt(iscsi.fd);
	if(rpkt->hdr->op == 0x25) {
		if(data->count != 0 && data->write == 0)
			memmove(data->p, rpkt->data, data->count);
		if(debug) {
			if((pkt->hdr->max[0] & 0xFF) == ScmdRsense) {
				fprint(2, "sense data:");
				for (n = 0; n < data->count; n++)
					fprint(2, " %2.2x", data->p[n] & 0xFF);
				fprint(2, "\n");
			}
		}

		rcount = nhgetl(rpkt->hdr->rcount);
		if(debug)
			fprint(2, "residue: %ld\n", rcount);

		if((pkt->hdr->max[0] & 0xFF) == ScmdReportlun) {
			data->count = nhgetl(rpkt->data);
			rcount = 0;
		}

		if(!(rpkt->hdr->flags & 0x01)) {
			freepkt(rpkt);
			rpkt = readpkt(iscsi.fd);
		}
	}

	if(debug) {
		fprint(2, "hdr:");
		for (n = 0; n < 48; n++)
			fprint(2, " %.2ux", *(rpkt->buf + n) & 0xFF);
		fprint(2, "\n");
	}

	if(rpkt->hdr->op != 0x21 && rpkt->hdr->op != 0x25)
		goto reset;

	if(debug)
		fprint(2, "status: %.2ux\n", rpkt->hdr->spec2 & 0xFF);

	switch(rpkt->hdr->spec2 & 0xFF) {
	case 0x00:
		*status = STok;
		break;
	default:
		*status = STcheck;
		break;
	}

	freepkt(rpkt);
	freepkt(pkt);

	return data->count - rcount;

reset:
	*status = STharderr;

	freepkt(rpkt);
	freepkt(pkt);

	return -1;
}

void
rattach(Req *r)
{
	r->ofcall.qid.path = PATH(Qdir, 0);
	r->ofcall.qid.type = dirtab[Qdir].mode >> 24;
	r->fid->qid = r->ofcall.qid;
	respond(r, nil);
}

char*
rwalk1(Fid *fid, char *name, Qid *qid)
{
	int i, n;
	char buf[32];
	ulong path;

	path = fid->qid.path;
	if(!(fid->qid.type & QTDIR))
		return "walk in non-directory";

	if(strcmp(name, "..") == 0){
		switch(TYPE(path)) {
		case Qn:
			qid->path = PATH(Qn, NUM(path));
			qid->type = dirtab[Qn].mode >> 24;
			return nil;
		case Qdir:
			return nil;
		default:
			return "bug in rwalk1";
		}
	}

	i = TYPE(path) + 1;
	for(; i < nelem(dirtab); i++) {
		if(i == Qn){
			n = atoi(name);
			snprint(buf, sizeof buf, "%d", n);
			if(n < (iscsi.maxlun & 0xFF) && strcmp(buf, name) == 0){
				qid->path = PATH(i, n);
				qid->type = dirtab[i].mode >> 24;
				return nil;
			}
			break;
		}
		if(strcmp(name, dirtab[i].name) == 0) {
			qid->path = PATH(i, NUM(path));
			qid->type = dirtab[i].mode >> 24;
			return nil;
		}
		if(dirtab[i].mode & DMDIR)
			break;
	}
	return "directory entry not found";
}

void
dostat(int path, Dir *d)
{
	Dirtab *t;

	memset(d, 0, sizeof(*d));
	d->uid = estrdup9p(owner);
	d->gid = estrdup9p(owner);
	d->qid.path = path;
	d->atime = d->mtime = starttime;
	t = &dirtab[TYPE(path)];
	if(t->name)
		d->name = estrdup9p(t->name);
	else {
		d->name = smprint("%ud", NUM(path));
		if(d->name == nil)
			sysfatal("out of memory");
	}
	if(TYPE(path) == Qdata)
		d->length = iscsi.lun[NUM(path)].capacity;
	d->qid.type = t->mode>>24;
	d->mode = t->mode;
}

static int
dirgen(int i, Dir *d, void*)
{
	i += Qdir + 1;
	if(i <= Qn) {
		dostat(i, d);
		return 0;
	}
	i -= Qn;
	if(i < (iscsi.maxlun & 0xFF)) {
		dostat(PATH(Qn, i), d);
		return 0;
	}
	return -1;
}

static int
lungen(int i, Dir *d, void *aux)
{
	int *c;

	c = aux;
	i += Qn + 1;
	if(i <= Qdata){
		dostat(PATH(i, NUM(*c)), d);
		return 0;
	}
	return -1;
}

void
rstat(Req *r)
{
	dostat((long)r->fid->qid.path, &r->d);
	respond(r, nil);
}

void
ropen(Req *r)
{
	ulong path;

	path = r->fid->qid.path;
	switch(TYPE(path)) {
	case Qraw:
		iscsi.lun[NUM(path)].phase = Pcmd;
		break;
	}
	respond(r, nil);
}

void
rread(Req *r)
{
	char buf[8192], *p;
	uchar i;
	ulong path;
	int bno, nb, len, offset, n;

	path = r->fid->qid.path;
	switch(TYPE(path)) {
	case Qdir:
		dirread9p(r, dirgen, 0);
		break;
	case Qn:
		dirread9p(r, lungen, &path);
		break;
	case Qctl:
		n = 0;
		for(i = 0; i < iscsi.maxlun; i++) {
			n += snprint(buf + n, sizeof(buf) - n, "%d: ", (int)(i & 0xFF));
			if(iscsi.lun[i].flags & Finqok)
				n += snprint(buf + n, sizeof(buf) - n, "inquiry %.48s ", (char *)iscsi.lun[i].inquiry + 8);
			if(iscsi.lun[i].blocks > 0)
				n += snprint(buf + n, sizeof(buf) - n, "geometry %ld %ld", iscsi.lun[i].blocks, iscsi.lun[i].lbsize);
			n += snprint(buf + n, sizeof(buf) - n, "\n");
		}
		readbuf(r, buf, n);
		break;
	case Qcctl:
		if(iscsi.lun[NUM(path)].lbsize <= 0) {
			respond(r, "no media on this lun");
			return;
		}

		n = snprint(buf, sizeof(buf), "inquiry %.48s ", (char *)iscsi.lun[NUM(path)].inquiry + 8);
		if(iscsi.lun[NUM(path)].blocks > 0)
			n += snprint(buf + n, sizeof(buf) - n, "geometry %ld %ld", iscsi.lun[NUM(path)].blocks, iscsi.lun[NUM(path)].lbsize);
		n += snprint(buf + n, sizeof(buf) - n, "\n");
		readbuf(r, buf, n);
		break;
	case Qraw:
		if(iscsi.lun[NUM(path)].lbsize <= 0) {
			respond(r, "no media on this lun");
			return;
		}
		switch(iscsi.lun[NUM(path)].phase) {
		case Pcmd:
			respond(r, "phase error");
			return;
		case Pdata:
			iscsi.lun[NUM(path)].data.p = (uchar*)r->ofcall.data;
			iscsi.lun[NUM(path)].data.count = r->ifcall.count;
			iscsi.lun[NUM(path)].data.write = 0;
			n = iscsirequest(&iscsi.lun[NUM(path)], &iscsi.lun[NUM(path)].cmd,
					&iscsi.lun[NUM(path)].data, &iscsi.lun[NUM(path)].status);
			iscsi.lun[NUM(path)].phase = Pstatus;
			if (n == -1) {
				respond(r, "IO error");
				return;
			}
			r->ofcall.count = n;
			break;
		case Pstatus:
			n = snprint(buf, sizeof(buf), "%11.0ud ", iscsi.lun[NUM(path)].status);
			if (r->ifcall.count < n)
				n = r->ifcall.count;
			memmove(r->ofcall.data, buf, n);
			r->ofcall.count = n;
			iscsi.lun[NUM(path)].phase = Pcmd;
			break;
		}
		break;
	case Qdata:
		if(iscsi.lun[NUM(path)].lbsize <= 0) {
			respond(r, "no media on this lun");
			return;
		}
		bno = r->ifcall.offset / iscsi.lun[NUM(path)].lbsize;
		nb = (r->ifcall.offset + r->ifcall.count + iscsi.lun[NUM(path)].lbsize - 1)
				/ iscsi.lun[NUM(path)].lbsize - bno;
		if(bno + nb > iscsi.lun[NUM(path)].blocks)
			nb = iscsi.lun[NUM(path)].blocks - bno;
		if(bno >= iscsi.lun[NUM(path)].blocks || nb == 0) {
			r->ofcall.count = 0;
			break;
		}
		if(nb * iscsi.lun[NUM(path)].lbsize > MaxIOsize)
			nb = MaxIOsize / iscsi.lun[NUM(path)].lbsize;
		p = malloc(nb * iscsi.lun[NUM(path)].lbsize);
		if (p == 0) {
			respond(r, "no mem");
			return;
		}
		iscsi.lun[NUM(path)].offset = r->ifcall.offset / iscsi.lun[NUM(path)].lbsize;
		n = SRread(&iscsi.lun[NUM(path)], p, nb * iscsi.lun[NUM(path)].lbsize);
		if(n == -1) {
			free(p);
			respond(r, "IO error");
			return;
		}
		len = r->ifcall.count;
		offset = r->ifcall.offset % iscsi.lun[NUM(path)].lbsize;
		if(offset + len > n)
			len = n - offset;
		r->ofcall.count = len;
		memmove(r->ofcall.data, p + offset, len);
		free(p);
		break;
	}
	respond(r, nil);
}

void
rwrite(Req *r)
{
	int n;
	char *p;
	int bno, nb, len, offset;
	Cmdbuf *cb;
	Cmdtab *ct;
	ulong path;

	n = r->ifcall.count;
	r->ofcall.count = 0;
	path = r->fid->qid.path;
	switch(TYPE(path)) {
	case Qctl:
		cb = parsecmd(r->ifcall.data, n);
		ct = lookupcmd(cb, cmdtab, nelem(cmdtab));
		if(ct == 0) {
			respondcmderror(r, cb, "%r");
			return;
		}
		switch(ct->index) {
		case CMreset:
			iscsireset(&iscsi);
		}
		break;
	case Qraw:
		if(iscsi.lun[NUM(path)].lbsize <= 0) {
			respond(r, "no media on this lun");
			return;
		}
		n = r->ifcall.count;
		switch(iscsi.lun[NUM(path)].phase) {
		case Pcmd:
			if(n != 6 && n != 10) {
				respond(r, "bad command length");
				return;
			}
			memmove(iscsi.lun[NUM(path)].rawcmd, r->ifcall.data, n);
			iscsi.lun[NUM(path)].cmd.p = iscsi.lun[NUM(path)].rawcmd;
			iscsi.lun[NUM(path)].cmd.count = n;
			iscsi.lun[NUM(path)].cmd.write = 1;
			iscsi.lun[NUM(path)].phase = Pdata;
			break;
		case Pdata:
			iscsi.lun[NUM(path)].data.p = (uchar*)r->ifcall.data;
			iscsi.lun[NUM(path)].data.count = n;
			iscsi.lun[NUM(path)].data.write = 1;
			n = iscsirequest(&iscsi.lun[NUM(path)], &iscsi.lun[NUM(path)].cmd,
					&iscsi.lun[NUM(path)].data, &iscsi.lun[NUM(path)].status);
			iscsi.lun[NUM(path)].phase = Pstatus;
			if(n == -1) {
				respond(r, "IO error");
				return;
			}
			break;
		case Pstatus:
			iscsi.lun[NUM(path)].phase = Pcmd;
			respond(r, "phase error");
			return;
		}
		break;	
	case Qdata:
		if(iscsi.lun[NUM(path)].lbsize <= 0) {
			respond(r, "no media on this lun");
			return;
		}
		bno = r->ifcall.offset / iscsi.lun[NUM(path)].lbsize;
		nb = (r->ifcall.offset + r->ifcall.count + iscsi.lun[NUM(path)].lbsize-1)
					/ iscsi.lun[NUM(path)].lbsize - bno;
		if(bno + nb > iscsi.lun[NUM(path)].blocks)
			nb = iscsi.lun[NUM(path)].blocks - bno;
		if(bno >= iscsi.lun[NUM(path)].blocks || nb == 0) {
			r->ofcall.count = 0;
			break;
		}
		if(nb * iscsi.lun[NUM(path)].lbsize > MaxIOsize)
			nb = MaxIOsize / iscsi.lun[NUM(path)].lbsize;
		p = malloc(nb * iscsi.lun[NUM(path)].lbsize);
		if(p == nil) {
			respond(r, "no mem");
			return;
		}
		offset = r->ifcall.offset % iscsi.lun[NUM(path)].lbsize;
		len = r->ifcall.count;
		if(offset || (len % iscsi.lun[NUM(path)].lbsize)) {
			iscsi.lun[NUM(path)].offset = r->ifcall.offset / iscsi.lun[NUM(path)].lbsize;
			n = SRread(&iscsi.lun[NUM(path)], p, nb * iscsi.lun[NUM(path)].lbsize);
			if(n == -1) {
				free(p);
				respond(r, "IO error");
				return;
			}
			if(offset + len > n)
				len = n - offset;
		}
		memmove(p+offset, r->ifcall.data, len);
		iscsi.lun[NUM(path)].offset = r->ifcall.offset / iscsi.lun[NUM(path)].lbsize;
		n = SRwrite(&iscsi.lun[NUM(path)], p, nb * iscsi.lun[NUM(path)].lbsize);
		if(n == -1) {
			free(p);
			respond(r, "IO error");
			return;
		}
		if(offset+len > n)
			len = n - offset;
		r->ofcall.count = len;
		free(p);
		break;
	}
	r->ofcall.count = n;
	respond(r, nil);
}

Srv usbssrv = {
	.attach = rattach,
	.walk1 = rwalk1,
	.open = ropen,
	.read = rread,
	.write = rwrite,
	.stat = rstat,
};

void
usage(void)
{
	fprint(2, "Usage: %s [-dDT] [-m mountpoint] [-s srvname] host volume\n", argv0);
	exits("Usage");
}

void
main(int argc, char **argv)
{
	char *srvname, *mntname;

	mntname = "/n/iscsi";
	srvname = nil;

	ARGBEGIN {
	case 'd':
		debug++;
		break;
	case 'm':
		mntname = EARGF(usage());
		break;
	case 's':
		srvname = EARGF(usage());
		break;
	case 'T':
		tls++;
		break;
	case 'D':
		++chatty9p;
		break;
	default:
		usage();
	} ARGEND;

	if(argc < 2)
		usage();
	host = argv[0];
	vol = argv[1];

	iscsiconnect(&iscsi);
	if(iscsiinit(&iscsi) < 0)
		sysfatal("iscsiinit failed");
	starttime = time(0);
	owner = getuser();

	postmountsrv(&usbssrv, srvname, mntname, 0);

	exits(0);
}


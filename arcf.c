#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define HS 32

struct arcf {
	unsigned int i, j, k;
	unsigned char s[256], r[256];
};

void hash(struct arcf *dgst, unsigned char *data, int size) {
	unsigned int i = dgst->i, j = dgst->j, k = dgst->k;
	unsigned char *s = dgst->s, *r = dgst->r;
	unsigned char c = 0;
	int x, y, z, n = size;
	if (size < 0) {
		i = 0; j = 0; k = 0;
		for (z = 0; z < 256; z++) {
			s[z] = z; r[z] = z;
			k = (((k + 1) * z) % 256);
		}
	}
	else {
		if ((size < 1) && (data == NULL)) {
			n = (256 * 16);
		}
		for (z = 0; z < n; z++) {
			if (size > 0) { c = data[z]; }
			else { c = s[k]; }
			i = ((i + 1) % 256);
			j = (((j << 1) ^ (s[i] + c)) % 256);
			x = s[i]; s[i] = s[j]; s[j] = x;
			k = (((k << 1) ^ (j + s[c])) % 256);
		}
		if ((size < 1) && (data == NULL)) {
			for (y = 0; y < HS; y++) {
				r[y] = (r[y] ^ s[k]);
				k = ((k + r[y]) % 256);
			}
		}
	}
	dgst->i = i; dgst->j = j; dgst->k = k;
}

void hmac(struct arcf *dgst, unsigned char *data, int size, unsigned char *skey, int slen) {
	struct arcf pkey;
	struct arcf *hkey = &pkey;
	int x, blen = HS;
	unsigned char opad[blen], ipad[blen];
	unsigned char *ukey = hkey->r;
	hash(hkey, NULL, -1); hash(hkey, skey, slen); hash(hkey, NULL, 0);
	for (x = 0; x < blen; ++x) {
		opad[x] = (ukey[x] ^ 0x5c); ipad[x] = (ukey[x] ^ 0x36);
	}
	/* ipad */
	hash(hkey, NULL, -1);
	hash(hkey, ipad, blen);
	hash(hkey, data, size);
	hash(hkey, NULL, 0);
	/* opad */
	hash(dgst, NULL, -1);
	hash(dgst, opad, blen);
	hash(dgst, ukey, blen);
	hash(dgst, NULL, 0);
}

int fill(unsigned char *buff, int size) {
	int l, retl = 0;
	while (size > 0) {
		l = read(STDIN_FILENO, &(buff[retl]), size);
		if (l < 1) { break; }
		retl += l; size -= l;
	}
	return retl;
}

int main(int argc, char **argv) {
	char *h = "0123456789abcdef";
	unsigned char t[32], o[96], b[9000], *z;
	struct arcf p;
	struct arcf *r = &p;
	int l, m = 0;
	if (argc < 2) {
		hash(r, NULL, -1);
		while (1) {
			bzero(b, 8192);
			l = fill(b, 8192);
			if (l < 1) { break; }
			hash(r, b, l);
		}
		hash(r, NULL, 0);
		m = 1;
	} else if (argc < 3) {
		bzero(b, 8192);
		l = fill(b, 8192);
		hmac(r, b, l, (unsigned char *)argv[1], strlen(argv[1]));
		m = 1;
	} else {
		z = (unsigned char *)argv[1];
		while (1) {
			bzero(b, HS);
			l = fill(b, HS);
			if ((l < 1) && (m > 0)) { break; }
			if (m == 0) {
				hmac(r, b, HS, z, strlen((const char *)z));
				if (argv[2][0] == 'e') {
					for (int y = 0; y < HS; ++y) { t[y] = r->r[y]; printf("%c", t[y]); }
					hmac(r, t, HS, z, strlen((const char *)z));
				}
			}
			if ((argv[2][0] == 'e') || (m > 0)) {
				for (int y = 0; y < HS; ++y) {
					o[y] = (b[y] ^ r->r[y]);
					t[y] = r->r[y]; printf("%c", o[y]);
				}
				if (argv[2][0] == 'e') { z = o; } else { z = b; }
				hmac(r, z, HS, t, HS);
			}
			++m;
		}
		m = 9;
	}
	if (m == 1) {
		bzero(o, 96);
		for (int y = 0; y < (HS * 2); y += 2) {
			o[y] = h[r->r[y/2]>>4];
			o[y+1] = h[r->r[y/2]&0xf];
		}
		printf("%s\n", o);
	}
	return 0;
}

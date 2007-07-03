/*
 * Copyright (C) 2007, Sébastien Le Ray
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-sqlite.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Get shadow information using username.
 */

enum nss_status _nss_sqlite_getspnam_r(const char* name, struct spwd *spbuf,
               char *buf, size_t buflen, int *errnop) {
    sqlite3 *pDb;
    int name_length;
    int pw_length;
    const unsigned char* pw;
    struct sqlite3_stmt* pSt;
    int res;
    const char* sql = "SELECT passwd FROM shadow WHERE username = ?";

    NSS_DEBUG("getspnam_r: looking for user %s (shadow)\n", name);


    if(!open_and_prepare(&pDb, &pSt, sql)) {
        return NSS_STATUS_UNAVAIL;
    }

    if(sqlite3_bind_text(pSt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        sqlite3_finalize(pSt);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    res = fetch_first(pDb, pSt);
    if(res != NSS_STATUS_SUCCESS) {
        return res;
    }
    
    /* SQLITE_ROW was returned, fetch data */
    pw = sqlite3_column_text(pSt, 0);
    name_length = strlen(name) + 1;
    pw_length = strlen(pw) + 1;
    if(buflen < name_length + pw_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    strcpy(buf, name);
    spbuf->sp_namp = buf;
    buf += name_length;
    strcpy(buf, pw);
    spbuf->sp_pwdp = buf;
    sqlite3_finalize(pSt);
    sqlite3_close(pDb);

    return NSS_STATUS_SUCCESS;
}



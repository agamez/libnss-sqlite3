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
    struct sqlite3_stmt* pSquery;
    int res;
    struct spwd entry;
    char* query;

    NSS_DEBUG("getspnam_r: looking for user %s (shadow)\n", name);

    if(sqlite3_open(NSS_SQLITE_SHADOW_DB, &pDb) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    if(!(query = get_query(pDb, "getspnam_r")) ) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }


    if(sqlite3_prepare(pDb, query, strlen(query), &pSquery, NULL) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return FALSE;
    }

    if(sqlite3_bind_text(pSquery, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }


    res = res2nss_status(sqlite3_step(pSquery), pDb, pSquery);
    if(res != NSS_STATUS_SUCCESS) {
        free(query);
        return res;
    }

    fill_shadow_sql(&entry, pSquery);
    res = fill_shadow(spbuf, buf, buflen, entry, errnop);

    free(query);
    sqlite3_finalize(pSquery);
    sqlite3_close(pDb);

    return res;
}

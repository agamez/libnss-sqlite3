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

#ifndef NSS_SQLITE_UTILS_H
#define NSS_SQLITE_UTILS_H

#include <sqlite3.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

char *get_query(struct sqlite3*, char*);

enum nss_status fill_passwd(struct passwd*, char*, size_t, struct passwd, int*);
inline void fill_passwd_sql(struct passwd*, struct sqlite3_stmt*);

enum nss_status fill_shadow(struct spwd*, char*, size_t, struct spwd, int*);
inline void fill_shadow_sql(struct spwd*, struct sqlite3_stmt*);

enum nss_status fill_group(struct sqlite3*, struct group*, char*, size_t,
    const unsigned char*, const unsigned char*, gid_t, int*);

#endif

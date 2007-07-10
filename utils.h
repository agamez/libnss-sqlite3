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

int open_and_prepare(sqlite3**, struct sqlite3_stmt**, const char*);
int open_and_prepare_sp(sqlite3**, struct sqlite3_stmt**, const char*);
int fetch_first(struct sqlite3*, struct sqlite3_stmt*);
enum nss_status fill_passwd(struct passwd*, char*, size_t, const char*,
    const char*, uid_t, gid_t, const char*, const char*, const char*, int*);
enum nss_status fill_group(struct sqlite3*, struct group*, char*, size_t,
    const unsigned char*, const unsigned char*, gid_t, int*);

#endif

 INSTALLATION
===============

This file explains post compilation steps. It assumes that libnss-sqlite
is compiled and in system libraries directory (/lib).


 1. Create database
--------------------

libnss-sqlite use two SQLite databases to provide authentication services.
Thus the first thing you have to do is to create these DB. Depending on your
sources configuration, you may use one or two DB (--with-passwd-db &
--with-shadow-db switches). Default configuration uses 2 databases:
/var/db/passwd.sqlite and /var/db/shadow.sqlite, we'll use these here:

cd libnss-sqlite
sudo mkdir /var/db
sudo sqlite3 -init conf/passwd.sql /var/db/passwd.sqlite
sudo sqlite3 -init conf/shadow.sql /var/db/shadow.sqlite
sudo chmod o-r /var/db/shadow.sqlite

That's all, databases are ready. Of course, it's up to you to populate them!
Currently, there is no way to customise database fields and tables' names.

 2. Configure nsswitch.conf
----------------------------

The second step is to tell glibc that we use this lib. Open /etc/nsswitch.conf
and add sqlite at the end of the passwd, groups and shadow lines. You should
obtain something like :

# ...
passwd:         compat sqlite
group:          compat sqlite
shadow:         compat sqlite
# ...

 3. Test
---------

Insert some records into SQLite db tables, open a new shell (nsswitch.conf is
only read when a new application is launched) and try id [user in SQLite DB].

 4. Limitations
----------------

libnss-sqlite only handle users which are in its DB. You can't have an external
user linked to a DB stored group. This is because additional groups lookup use
username and is quite ugly to implement.

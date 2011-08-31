CREATE TABLE shadow (username TEXT PRIMARY KEY, passwd TEXT, lastchange INTEGER default -1, mindays INTEGER default -1, maxdays INTEGER default -1, warn INTEGER default -1, inact INTEGER default -1, expire INTEGER default -1);

CREATE TABLE nss_queries(name TEXT PRIMARY KEY, query TEXT NOT NULL);
INSERT INTO nss_queries VALUES("getspnam_r","SELECT username, passwd, lastchange, mindays, maxdays, warn, inact, expire FROM shadow WHERE username = ?");

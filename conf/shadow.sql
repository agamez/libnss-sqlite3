CREATE TABLE shadow (username TEXT PRIMARY KEY, passwd TEXT);

CREATE TABLE nss_queries(name TEXT PRIMARY KEY, query TEXT NOT NULL);
INSERT INTO nss_queries VALUES("getspnam_r","SELECT passwd FROM shadow WHERE username = ?");

CREATE TABLE shadow (username TEXT PRIMARY KEY, passwd TEXT);

CREATE TABLE queries(name TEXT PRIMARY KEY, query TEXT NOT NULL);
INSERT INTO queries VALUES("getspnam_r","SELECT passwd FROM shadow WHERE username = ?");

INSERT INTO Login(unitNo, role, username, hash, salt) -- password Pa$$w0rd
VALUES (null, 1, 'admin', '8ec04993179a94061528e942f3387bc9c75b82f89979501846b9dfcceed6c83a', '1234567890');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES ('A', 2, 'amer', '3d52acacc7a3ac43d96ab730deccda0a04b49746e28fe12e43a5c4cdd1d0ece2', '0987654321');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES ('M', 2, 'marija', 'b9d47ac23da5ec4647273873b13eaccd1018304f5950626b56dcc8e9be54ec87', '1111111111');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES ('P', 2, 'apdifata', '39154a015a47f7db973be35960e7371f333ae939e75469954bca23a548c31390', '2222222222');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES ('J', 2, 'jonathan', '135c076859e0cc6d64554c019a7e4c76bcec79716c54ee573e6f733cbe92f0ee', '3333333333');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES (null, 4, 'stat1', '39154a015a47f7db973be35960e7371f333ae939e75469954bca23a548c31390', '2222222222');

INSERT INTO Login(unitNo, role, username, hash, salt) --password 12345678
VALUES (null, 4, 'stat2', '135c076859e0cc6d64554c019a7e4c76bcec79716c54ee573e6f733cbe92f0ee', '3333333333');

INSERT INTO Board(day, slot, login)
VALUES ('2021-06-25', 2, 2);

INSERT INTO Board(day, slot, login)
VALUES ('2021-06-25', 1, 3);

INSERT INTO Board(day, slot, login)
VALUES ('2021-06-25', 3, 4);

INSERT INTO Board(day, slot, login)
VALUES ('2021-06-26', 2, 5);

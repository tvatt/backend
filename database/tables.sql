SET TIMEZONE='Europe/Stockholm';

CREATE TABLE Login
(
    id       BIGSERIAL PRIMARY KEY,
    unitNo   varchar(10) null
        UNIQUE,
    username varchar(50) not null
        UNIQUE,
    role     smallint    not null  -- 1-admin, 2-book, 4-stat
        DEFAULT 2,
    hash     char(64)    not null, -- sha265 output 64char
    salt     char(10)    not null, -- 10 random char
    CONSTRAINT Login_unitNo_role_CK -- unitNo must be not null if user role is booker
        CHECK ( role & 2 <> 2 or (unitNo is not null) )
);

CREATE TABLE Board
(
    id    BIGSERIAL PRIMARY KEY,
    day   char(10) not null, -- date format yyyy-mm-dd
    slot  smallint not null, -- 1, 2, 3 only accepted
    login integer  not null
        UNIQUE
        REFERENCES Login (id),
    CONSTRAINT Board_day_slot_UQ UNIQUE (day, slot)
);

CREATE TABLE Statistics
(
	id bigserial PRIMARY KEY,
	datetime     timestamp    null
	             DEFAULT now(),
	action       varchar(60)  null,
	username     varchar(50)  null
);

'use strict';

const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const authCachesList = [];
const ADMIN = 'admin';
const TTL_CACHE = process.env.TTL_CACHE || 0; // 0 sec

const STAT_ACTIONS = {
  login: "Login",
  getBoard: "get Board",
  changeBooking: "Change Booking",
  changePassword: "Change Password",
}

const AUTH_ROLES = {
  admin: 'admin',
  booker: 'booker',
  statistician: 'statistician',
}

async function getUsers() {
  const sqlStmt = `SELECT id, unitNo AS "unitNo", username, role FROM Login WHERE role & 1 = 0 AND username <> '${ADMIN}'`;
  const client = await pool.connect();
  try {
    const result = await client.query(sqlStmt);
    addRolesArrayToResult(result.rows);
    return (result.rows);
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function getUserByUsername(username) {
  console.debug("Add statistics Login");
  const sqlStmt = `SELECT id, unitNo As "unitNo", username, role
                   FROM Login
                   WHERE username = $1`;
  const client = await pool.connect();
  try {
    const result = await client.query(sqlStmt, [username]);
    addRolesArrayToResult(result.rows);
    addStatistics(STAT_ACTIONS.login, username);
    return result.rows[0];
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function getBoard() {
  console.debug("Add statistics Get Board");
  const sqlStmt = `
      SELECT b.id AS id, b.day AS day, slot, l.username AS username, l.unitNo AS "unitNo"
      FROM Board b
               LEFT JOIN Login l on b.login = l.id;`; // unitNo need to be quoted to keep the case sensitive other wise postgresql driver will convert it into unitno

  const client = await pool.connect();
  try {
    const result = await client.query(sqlStmt);
    addStatistics(STAT_ACTIONS.getBoard, null);
    return result.rows;
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

async function deleteUserBooking(username) {
  console.debug("Add statistics Change Booking");
  // DELETE ALL booking of the user
  const client = await pool.connect();
  try {
    const sqlStmt = `DELETE
                     FROM Board
                     WHERE login IN (SELECT id FROM Login WHERE username = $1);`;
    await client.query(sqlStmt, [username]);
    addStatistics(STAT_ACTIONS.changeBooking, username);
    return true;
  } catch (err) {
    console.error(err);
    return false
  } finally {
    client.release();
  }
}

/**
 *
 * @param {string} username
 * @param {string} day - date format "yyyy-mm-dd" ex. "2021-03-11"
 * @param {number} slot
 * @returns {Promise<boolean>} - returns true when success
 */
async function addBooking(username, day, slot) {
  const client = await pool.connect();
  try {
    const sqlStmt = `INSERT INTO Board (day, slot, login)
                     SELECT $1, $2, id
                     FROM Login
                     WHERE username = $3`;
    const result = await client.query(sqlStmt, [day, slot, username]);
    return result.rowCount === 1;
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

/**
 * @param {{unitNo: string, username: string, password: string, roles: string[]}} newUser
 * @returns {Promise<boolean>}
 */
async function addUser(newUser) {
  const client = await pool.connect();
  try {
    const salt = getRandomSalt();
    const hash = getHashedPassword(newUser.password, salt);
    const roles = newUser.roles || ['booker'];
    const role = getRoleFromRolesArray(roles);
    let unitNo;
    if (typeof newUser.unitNo === 'string' && newUser.unitNo.length > 0) {
      unitNo = newUser.unitNo;
    } else {
      unitNo = null;
    }
    const sqlStmt = `INSERT INTO Login(unitNo, username, role, hash, salt)
                     VALUES ($1, $2, $3, $4, $5)`;
    const result = await client.query(sqlStmt, [unitNo, newUser.username, role, hash, salt]);
    return result.rowCount === 1;
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function deleteUser(loginId) {
  const client = await pool.connect();
  try {
    const sqlStmtDelLogin = `DELETE FROM Board WHERE login = $1`;
    await client.query(sqlStmtDelLogin, [loginId]);
    const sqlStmtDelBoard = `DELETE FROM Login WHERE id = $1 AND username <> '${ADMIN}'`;
    const result = await client.query(sqlStmtDelBoard, [loginId]);
    return result.rowCount === 1;
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function updateUsername(loginId, newUsername, authUser) {
  const client = await pool.connect();
  try {
    let sqlStmt;
    let result;
    if (authUser === ADMIN) {
      sqlStmt = `UPDATE Login SET username = $1 WHERE id = $2 AND username <> '${ADMIN}'`;
      result = await client.query(sqlStmt, [newUsername, loginId]);
    } else {
      sqlStmt = `UPDATE Login SET username = $1 WHERE id = $2 AND username = $3 AND username <> '${ADMIN}'`;
      result = await client.query(sqlStmt, [newUsername, loginId, authUser]);
    }
    return result.rowCount === 1;
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function resetPassword(loginId, newPassword) {
  const client = await pool.connect();
  try {
    const salt = getRandomSalt();
    const hash = getHashedPassword(newPassword, salt);
    const sqlStmt = `UPDATE Login SET hash = $1, salt = $2 WHERE id = $3`;
    const result = await client.query(sqlStmt, [hash, salt, loginId]);
    return result.rowCount === 1;
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function changePassword(username, password, newPassword) {
  console.debug("Add statistics Change Password");
  const client = await pool.connect();
  try {
    const dbUser = await getUserAuthFromDb(username);
    const hash = getHashedPassword(password, dbUser.salt)
    const newSalt = getRandomSalt();
    const newHash = getHashedPassword(newPassword, newSalt);
    const sqlStmt = `UPDATE Login SET hash = $1, salt = $2 WHERE username = $3 AND hash = $4`;
    const result = await client.query(sqlStmt, [newHash, newSalt, username, hash]);
    if (result.rowCount === 1) {
      removeFromCacheByUsername(username, password);
      addStatistics(STAT_ACTIONS.changePassword, username);
      return true;
    } else {
      return false;
    }
  } catch (err) {
    console.error(err);
    return false;
  } finally {
    client.release();
  }
}

async function addStatistics(action, username = null) {
  const client = await pool.connect();
  try {
    const sqlStmt = `INSERT INTO Statistics(datetime, action, username)
                   VALUES (now(), $1, $2)`;
    await client.query(sqlStmt, [action, username]);
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

async function getStatistics() {
  const client = await pool.connect();
  try {
    const sqlStmt = `SELECT action, COUNT(1) FROM Statistics GROUP BY action;`;
    const result = await client.query(sqlStmt);
    return result.rows;
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

/**
 *
 * @param {string} authorization
 * @param {boolean} useCache
 * @returns {boolean}
 */
async function isUserAuth(authorization, useCache = !!TTL_CACHE) {
  if (authorization != null && authorization.toLowerCase().startsWith("basic")) {
    if (useCache && isCached(authorization)) return true;
    const basicAuthUser = getBasicAuthUsernamePassword(authorization);
    const dbUser = await getUserAuthFromDb(basicAuthUser.username);
    if (dbUser != null && isHashEqualSaltedPassword(dbUser.hash, dbUser.salt, basicAuthUser.password)) {
      if (useCache) addToCache(authorization);
      return true;
    }
  }
  return false;
}

/**
 *
 * @param {string} authorization
 * @param {number} role
 * @returns {boolean}
 */
async function isUserAuthWithRole(authorization, role) {
  if (authorization != null && authorization.toLowerCase().startsWith("basic")) {
    const basicAuthUser = getBasicAuthUsernamePassword(authorization);
    const dbUser = await getUserAuthFromDb(basicAuthUser.username);
    if (
        dbUser != null
        && isHashEqualSaltedPassword(dbUser.hash, dbUser.salt, basicAuthUser.password)
        && (dbUser.role & role)
    ) {
      return true;
    }
  }
  return false;
}

/**
 *
 * @param {string} authorization
 * @returns {{username:string, password:string}}
 */
function getBasicAuthUsernamePassword(authorization) {
  const b64auth = (authorization || '').split(' ')[1] || ''
  const [username, password] = Buffer.from(b64auth, 'base64').toString().split(':')
  return { username, password };
}

/**
 *
 * @param {string} username
 * @returns {Promise<{username: string, role: number, hash: string, salt: string} | null>}
 */
async function getUserAuthFromDb(username) {
  const sqlStmt = `SELECT username, role, hash, salt
                   FROM Login
                   WHERE username = $1`;
  const client = await pool.connect();
  try {
    const result = await client.query(sqlStmt, [username]);
    if (result.rows.length === 1) {
      const r = result.rows[0];
      return {
        username: r.username,
        role: r.role,
        hash: r.hash,
        salt: r.salt,
      }
    }
    return null
  } catch (err) {
    console.error(err);
    return null;
  } finally {
    client.release();
  }
}

/**
 *
 * @param {string} authorization
 * @returns {boolean}
 */
function isCached(authorization) {
  const authCache = authCachesList.filter(it => it.auth === authorization)[0];

  if (authCache) {
    const ttl = TTL_CACHE * 1000;
    if (Date.now() - authCache.cacheTime > ttl) {
      removeFromCache(authCache.auth);
      return false;
    }
    return true;
  }
  return false;
}

/**
 * @param {string} authorization
 */
function removeFromCache(authorization) {
  const i = authCachesList.indexOf(authorization);
  if (i > -1) authCachesList.splice(i, 1);
}

/**
 * @param {string} username
 * @param {string} password
 */
function removeFromCacheByUsername(username, password) {
  removeFromCache('Basic ' + Buffer.from(username + ':' + password).toString('base64'));
}

let addToCacheCounter = 0;

/**
 * @param {string} authorization
 */
function addToCache(authorization) {
  authCachesList.push({
    auth: authorization,
    cacheTime: Date.now(),
  });
  addToCacheCounter++;
  if (addToCacheCounter > 100) {
    addToCacheCounter = 0;
    cleanCache();
  }
}

function cleanCache() {
  const ttl = TTL_CACHE * 1000;
  for (let i = authCachesList.length - 1; i > -1; i--) {
    if (Date.now() - authCachesList[i].cacheTime > ttl) {
      authCachesList.splice(i, 1);
    }
  }
}

/**
 *
 * @param {string} hash
 * @param {string} salt
 * @param {string} password
 * @returns {boolean}
 */
function isHashEqualSaltedPassword(hash, salt, password) {
  const incomingHash = crypto.createHash('sha256').update(password + salt).digest('hex');
  return hash === incomingHash;
}

/**
 * @param {string} password
 * @param {string} salt
 * @returns {string}
 */
function getHashedPassword(password, salt) {
  return crypto
      .createHash('sha256')
      .update(password + salt)
      .digest('hex');
}

/**
 * @returns {string} - 10 random char
 */
function getRandomSalt() {
  const result = [];
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 10; i++) {
    result.push(characters.charAt(Math.floor(Math.random() * characters.length)));
  }
  return result.join('');
}

/**
 * @param {{role: number}[]} rows
 */
function addRolesArrayToResult(rows) {
  rows.forEach(r => {
    const roles = [];
    if ((r.role & 1) === 1) roles.push(AUTH_ROLES.admin);
    if ((r.role & 2) === 2) roles.push(AUTH_ROLES.booker);
    if ((r.role & 4) === 4) roles.push(AUTH_ROLES.statistician);
    r.roles = roles;
  })
}

/**
 * @param {string[]} roles
 * @returns {number}
 */
function getRoleFromRolesArray(roles) {
  let role = 0;
  if (roles.indexOf(AUTH_ROLES.admin) !== -1) role += 1;
  if (roles.indexOf(AUTH_ROLES.booker) !== -1) role += 2;
  if (roles.indexOf(AUTH_ROLES.statistician) !== -1) role += 4;
  return role;
}

exports.isUserAuth = isUserAuth;
exports.isUserAuthWithRole = isUserAuthWithRole;
exports.getUsers = getUsers;
exports.getUserByUsername = getUserByUsername;
exports.getBoard = getBoard;
exports.deleteUserBooking = deleteUserBooking;
exports.updateUsername = updateUsername;
exports.addBooking = addBooking;
exports.addUser = addUser;
exports.deleteUser = deleteUser;
exports.resetPassword = resetPassword;
exports.changePassword = changePassword;
exports.getStatistics = getStatistics;

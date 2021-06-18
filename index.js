'use strict';

const Express = require('express');
const ExpressWs = require('express-ws');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./database/db');

const PORT = process.env.PORT || 3000
const ENV_SUFFIX = process.env.ENVIRONMENT ? '-' + process.env.ENVIRONMENT : ''
const ADMIN = 'admin';
const USERNAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.@+=_-]{0,49}$/g;
const PASSWORD_REGEX = /^.{8,50}$/g;
const DAY_REGEX = /^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])$/g;
const SLOT_REGEX = /^[123]$/g;

const AdminAuthResult = {
  NOT_ADMIN: 'Not Admin',
  INVALID_PASSWORD: 'Invalid Password',
  VALID: 'Valid',
}

const expressWs = ExpressWs(Express());
const app = expressWs.app;
const wss = expressWs.getWss();

const origins = cors({
  credentials: true,
  origin: [
    'http://localhost',
    'https://localhost',
    'https://tvatt.herokuapp.com',
    `http://se-hkr-tavla-fe${ENV_SUFFIX}.herokuapp.com`,
    `https://se-hkr-tavla-fe${ENV_SUFFIX}.herokuapp.com`,
  ],
});

app.use(origins);
app.use(bodyParser.json());
app.listen(PORT, () => console.log(`Listening on ${PORT}`))

wss.on('connection', (ws) => {
  console.debug('got new WebSocket connection');
});

app.options('*', origins);

app.get('/helloworld', async (req, res) => {
  try {
    res.status(200).send("Hello World!");
  } catch (err) {
    res.send('error');
  }
})

// user login
app.post('/api/login', async (req, res) => {
  try {
    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
    } else {
      res.status(200).send();
    }
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
});

app.get('/api/board', async (req, res) => {
  try {
    const result = await db.getBoard();
    res.status(200);
    res.json(result);
  } catch (e) {
    res.sendStatus(500)
  }
});

// make or change booking
app.post('/api/board', async (req, res) => {
  try {
    const [username] = getBasicAuthUsernamePassword(req.headers.authorization);

    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    const newDay = req.body.day;
    const newSlot = req.body.slot;

    if (!newDay.match(DAY_REGEX)) {
      res.status(400).send('date is invalid use format "yyyy-mm-dd" ex. "2021-03-21');
      return;
    }

    if (!newSlot.toString().match(SLOT_REGEX)) {
      res.status(400).send('slot is invalid, only (1, 2, 3) is accepted');
      return;
    }

    await db.deleteUserBooking(username);
    if (await db.addBooking(username, newDay, newSlot)) {
      notifyClientsAboutBookingChange().then(() => console.debug('client informed'));
      res.status(200).send();
    } else {
      res.status(500).send('error during changing booking in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// delete user booking
app.delete('/api/board', async (req, res) => {
  try {
    const [username] = getBasicAuthUsernamePassword(req.headers.authorization);

    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    await db.deleteUserBooking(username)
    notifyClientsAboutBookingChange().then(() => console.debug('clients informed'));
    res.sendStatus(200);
  } catch (e) {
    res.sendStatus(500)
  }
});

// delete booking by admin
app.delete('/api/board/:username', async (req, res) => {
  try {
    if (sendResponseWhenAdminNotAuth(await isAdminAuth(req.headers.authorization), res))
      return;

    await db.deleteUserBooking(req.params.username)
    res.status(200).send();
  } catch (e) {
    res.sendStatus(500)
  }
});

// get users
app.get('/api/user', async (req, res) => {
  try {
    if (sendResponseWhenAdminNotAuth(await isAdminAuth(req.headers.authorization), res))
      return;

    const result = await db.getUsers();
    if (result) {
      res.status(200).send(result);
    } else {
      res.status(500).send('error during getting users from database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// get one user
app.get('/api/user/:username', async (req, res) => {
  try {
    const [username] = getBasicAuthUsernamePassword(req.headers.authorization);
    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    if (username !== ADMIN && username !== req.params.username) {
      res.status(401).send('username must be admin or the user itself');
      return;
    }

    const result = await db.getUserByUsername(req.params.username);
    if (result) {
      res.status(200).send(result);
    } else {
      res.status(500).send('error during getting user from database');
    }
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// add new user
app.post('/api/user', async (req, res) => {
  try {
    /*if (sendResponseWhenAdminNotAuth(await isAdminAuth(req.headers.authorization), res))
      return;*/

    const newUser = {
      unitNo: req.body.unitNo,
      roles: req.body.roles,
      username: req.body.username,
      password: req.body.password,
    };

    if (!newUser.username.match(USERNAME_REGEX)) {
      res.status(400).send('username is invalid');
      return;
    }

    if (!newUser.password.match(PASSWORD_REGEX)) {
      res.status(400).send('password is invalid');
      return;
    }

    if (await db.addUser(newUser)) {
      console.log('user added');
      res.status(200).send();
    } else {
      res.status(500).send('error during adding user in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// delete new user
app.delete('/api/user/:userId', async (req, res) => {
  try {
    if (sendResponseWhenAdminNotAuth(await isAdminAuth(req.headers.authorization), res))
      return;

    if (await db.deleteUser(req.params.userId)) {
      console.log('user deleted');
      res.status(200).send();
    } else {
      res.status(500).send('error during deleting user in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// update username
app.put('/api/user/:userId', async (req, res) => {
  try {
    const [username] = getBasicAuthUsernamePassword(req.headers.authorization);

    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    const userId = req.params.userId
    if (!userId) {
      res.status(400).send('you need to provide user id to update it');
      return;
    }

    const newUsername = req.body.username;

    if (newUsername === ADMIN || !newUsername.match(USERNAME_REGEX)) {
      res.status(400).send('the new username is invalid');
      return;
    }

    if (await db.updateUsername(userId, newUsername, username)) {
      console.log('user updated');
      res.status(200).send();
    } else {
      res.status(400).send('error during update user in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// reset user password
app.post('/api/user/resetpassword/:userId', async (req, res) => {
  try {
    if (sendResponseWhenAdminNotAuth(await isAdminAuth(req.headers.authorization), res))
      return;

    const newPassword = req.body.password
    if (!newPassword.match(PASSWORD_REGEX)) {
      res.status(400).send('password is invalid');
      return;
    }

    if (await db.resetPassword(req.params.userId, newPassword)) {
      console.log('password reset by admin');
      res.status(200).send();
    } else {
      res.status(500).send('error during reset password in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// change password
app.post('/api/user/changepassword', async (req, res) => {
  try {
    const [username, password] = getBasicAuthUsernamePassword(req.headers.authorization);

    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    const newPassword = req.body.password
    if (!newPassword.match(PASSWORD_REGEX)) {
      res.status(400).send('password is invalid');
      return;
    }

    if (await db.changePassword(username, password, newPassword)) {
      console.log(`password changed by user: [${username}]`);
      res.status(200).send();
    } else {
      res.status(500).send('error during changing password in database');
    }
  } catch (e) {
    res.sendStatus(500)
  }
});

// GET statistics
app.get('/api/statistics', async (req, res) => {
  try {
    if (!await db.isUserAuth(req.headers.authorization)) {
      res.status(401).send('username or password is incorrect');
      return;
    }

    if (!await db.isUserAuthWithRole(req.headers.authorization, 4)
        && !await db.isUserAuthWithRole(req.headers.authorization, 1)) {
      res.status(401).send('user must has admin or statistician role');
      return;
    }

    const result = await db.getStatistics();
    if (result) {
      res.status(200).send(result);
    } else {
      res.status(500).send('error during getting statistics from database');
    }
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// debug WebSocket action.
app.ws('*', (ws, req) => {
  ws.on('message', (msg) => {
    console.debug('msg: ' + msg);
  });
  ws.on('close', (msg) => {
    console.debug('close: ' + msg);
  });
});

async function isAdminAuth(authorization) {
  const [username] = getBasicAuthUsernamePassword(authorization);

  if (username !== ADMIN) return AdminAuthResult.NOT_ADMIN;
  if (!await db.isUserAuth(authorization)) return AdminAuthResult.INVALID_PASSWORD;
  return AdminAuthResult.VALID;
}

function sendResponseWhenAdminNotAuth(adminAuthResult, res) {
  if (adminAuthResult === AdminAuthResult.NOT_ADMIN) {
    res.status(401).send('You need admin authentication');
    return true;
  }

  if (adminAuthResult === AdminAuthResult.INVALID_PASSWORD) {
    res.status(401).send('admin password is incorrect');
    return true;
  }

  if (adminAuthResult === AdminAuthResult.VALID)
    return false; // indicate that no response send back

  throw new Error('invalid result');
}

//TODO: move this function to common place like auth.js as it is repeated
function getBasicAuthUsernamePassword(authorization) {
  const b64auth = (authorization || '').split(' ')[1] || ''
  const [username, password] = Buffer.from(b64auth, 'base64').toString().split(':')
  return [username, password];
}

async function notifyClientsAboutBookingChange() {
  wss.clients.forEach((client) => {
    client.send(JSON.stringify({ type: 'booking changed', data: { _futureUse: 'hold new booking info' } }));
  });
}

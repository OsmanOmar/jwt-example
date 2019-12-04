require('dotenv/config')
const express = require('express');
const cookieParser = require('cookie-parser')
const cors = require('cors')
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");

const { fakeDB } = require('./fakeDB')
const { createAccessToken, createRefreshToken } = require('./tokens')
const { sendAccessToken, sendRefreshToken } = require('./tokens')
const { isAuth } = require('./isAuth')

// 1. register a user
// 2. login
// 3. logout
// 4. setup a protected route
// 5. get a new access token with a refresh token

const server = express();

server.use(cookieParser())

// use express middleware for easier cookie handling
server.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true
  })
)

// needed to be able to read body data
server.use(express.json())
server.use(express.urlencoded({ extended: true })) //  support url encoded bodies


// 1. register a user
server.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    // 1. check if user exists
    const user = fakeDB.find(user => user.email === email)
    if (user) {
      throw new Error('user already does exist')
    }

    // 2. if user does not exist, hash the password
    const hashedPassword = await hash(password, 10);

    // 3. insert the user in "database"
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword
    })

    res.send({ message: 'user created!' })

  } catch (error) {
    res.send({
      error: error.message
    })
  }
})

// 2. login
server.post('/login', async (req, res) => {
  const { email, password } = req.body

  try {
    const user = fakeDB.find(user => user.email === email)

    if (!user) {
      throw new Error('user does not exist')

    }

    const valid = await compare(password, user.password)
    if (!valid) {
      throw new Error('password is not correct')
    }

    const accessToken = createAccessToken(user.id)
    const refreshToken = createRefreshToken(user.id)

    // put refresh token in the database
    user.refreshToken = refreshToken;

    //  send token, refresh token as a cookie, access token as a res
    sendRefreshToken(res, refreshToken)
    sendAccessToken(req, res, accessToken)

  } catch (error) {
    res.send({
      error: error.message
    })
  }
})

// logout
server.post('/logout', (_req, res) => {
  res.clearCookie('refreshToken', { path: '/refresh-token' })
  return res.send({
    message: 'logged out!'
  })
})

// 4. protected route
server.post('/protected', async (req, res) => {
  try {
    const userId = isAuth(req)

    if (userId !== null) {
      res.send({
        data: 'protected data!'
      })
    }
  } catch (error) {
    res.send({
      error: error.message
    })
  }
})

// get a new access token with a refresh token
server.post('/refresh-token', (req, res) => {
  const token = req.cookies.refreshToken

  if (!token) {
    return res.send({ accessToken: '' })
  }

  // have a token, need verify
  let payload = null;

  try {
    payload = verify(token, process.env.refresh_token_secret)
  } catch (error) {
    return res.send({ accessToken: '' })
  }

  // token is valid, check if user does exist
  const user = fakeDB.find(user => user.id === payload.userId)

  if (!user) {
    return res.send({ accessToken: '' })
  }

  if (user.refreshToken !== token) {
    return res.send({
      accessToken: ''
    })
  }

  const accessToken = createAccessToken(user.id)
  const refreshToken = createRefreshToken(user.id)

  user.refreshToken = refreshToken;

  sendRefreshToken(res, refreshToken)

  return res.send({ accessToken })
})

server.listen(process.env.PORT, () => {
  console.log(`server is running on port ${process.env.PORT}`)
})



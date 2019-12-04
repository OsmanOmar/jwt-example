const {sign} =  require('jsonwebtoken')

const createAccessToken = userId => {
  return sign({userId}, process.env.access_token_secret, {
    expiresIn: '15m'
  })
}

const createRefreshToken = userId => {
  return sign({userId}, process.env.refresh_token_secret, {
    expiresIn: '7d'
  })
}

const sendAccessToken = (req, res, accessToken) => {
  res.send({
    accessToken,
    email: req.body.email
  })
}

const sendRefreshToken = (res, refreshToken) => {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    path: '/refresh-token'
  })
}

module.exports = {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken
}
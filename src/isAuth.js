const {verify} = require('jsonwebtoken')

const isAuth  = req => {
  const authorization  = req.headers['authorization'];

  if(!authorization) {
    throw new Error('you need to login')
  }

  const token = authorization.split(' ')[1];

  const {userId} = verify(
    token, process.env.access_token_secret)

    return userId
}



module.exports = {
  isAuth
}
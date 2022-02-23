const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../secrets')

function tokenBuilder (user){
    // console.log(JWT_SECRET)
    // return 'The awesome token'
    const payload = {
        subject : user.user_id,
        username : user.username,
        role_name : user.role_name,
    }
    const option = {
        expiresIn: '1d',
    }
    const token = jwt.sign(payload, JWT_SECRET, option)
    return token
}

module.exports = tokenBuilder
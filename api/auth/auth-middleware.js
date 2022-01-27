const { status } = require("express/lib/response");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const { findBy } = require('../users/users-model')
const jwt = require('jsonwebtoken')

const restricted = async (req, res, next) => {

  // TEST: http :9000/api/users
  // TEST: http :9000/api/users  Authorization:gogo
  // TEST: http :9000/api/users  Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0Ijo2LCJ1c2VybmFtZSI6ImJhciIsInJvbGVfbmFtZSI6InN0dWRlbnQiLCJpYXQiOjE2NDMzMTUzNjcsImV4cCI6MTY0MzQwMTc2N30.1DfIjcwFJKgUrr-p-5HBs0FiLSvQugjvII6ZDcPg06Q
  
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    // console.log("rest middleware!")
    // next()
    const token = req.headers.authorization
    if(!token) {
      return next({ status:401, message: 'token required'})
    } 
    jwt.verify(token, JWT_SECRET, (err, decodedToken)=>{
      if(err){
        next({status: 401, message: 'token invalid'})
      }else{
        req.decodedToken = decodedToken
        next()
      }
    })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    // console.log("only middleware!")
    // next()
    if(role_name === req.decodedToken.role_name){
      next()
    }else{
      next({ status: 403, message: 'This is not for you'})
    }
}

// TEST: http post :9000/api/auth/login username=bar password=1234
const checkUsernameExists = async(req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    // console.log("rest middleware!")
    // next()
    try{
      const [user] = await findBy({username: req.body.username})
      if(!user){
        next({status: 401, message: "Invalid credentials"})
      }else{
        req.user = user
        next()
      }
    }catch(err){
      next(err)
    }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
    // console.log("rest middleware!")
    // next()
    // TEST OK: http post :9000/api/auth/register username=foo password=1234 role_name='foo'
    // TEST ERR: http post :9000/api/auth/register username=foo password=1234 role_name='admin'
    // TEST ERR: http post :9000/api/auth/register username=foo password=1234 role_name='abcdefghijklmnorstivuxyzabcdefghijklmnorstivuxyz'
    if(!req.body.role_name || !req.body.role_name.trim()){
      req.role_name = 'student'
      next()
    }else if (req.body.role_name.trim() === 'admin'){
      next({status: 422, message: "Role name can not be admin"})
    }else if(req.body.role_name.trim().length > 32){
      next({status: 422, message:  "Role name can not be longer than 32 chars"})
    }else{
      req.role_name = req.body.role_name.trim()
      next()
    }
    
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}

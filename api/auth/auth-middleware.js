const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model');

const restricted = (req, res, next) => {
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
    console.log("restricted middleware!")
    next()
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
  console.log("only middleware!")
  next()
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  // console.log("checkUsernameExists middleware!")
  // next()
  try{
    // console.log(req.body.username)
    const existUser = await User.findBy({username: req.body.username})
    console.log(existUser[0])
    if(existUser){
      req.user = existUser[0]
      next()
    }else{
      next({"message": "Invalid credentials", status: 401})
    }
  }catch(err){
    next(err)
  }
}
// TEST OK: http post :9000/api/auth/register username=foo password=1234 role_name='foo'
// TEST ERR: http post :9000/api/auth/register username=foo password=1234 role_name='admin'
// TEST ERR: http post :9000/api/auth/register username=foo password=1234 role_name='abcdefghijklmnorstivuxyzabcdefghijklmnorstivuxyz'
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
  if(!req.body.role_name || !req.body.role_name.trim()){
    req.role_name = 'student'
    return next()
  }else if(req.body.role_name.trim() === 'admin'){
    return next({status: 422, message: "Role name can not be admin"})
  }else if(req.body.role_name.trim().length > 32){
    return next({status: 422, message: "Role name can not be longer than 32 chars"})
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

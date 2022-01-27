const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const User = require('../users/users-model');
const { default: jwtDecode } = require("jwt-decode");
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
   // TEST OK: http post :9000/api/auth/register username=foo password=1234 role_name=ceo
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
    User.add({ username, password: hash, role_name })
      .then( newUser=>{
        // res.status(201).json(newUser)
        res.status(201).json({
          user: newUser.user,
          username: newUser.username,
          role_name: newUser.role_name
        })
      } )
      .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  // res.json({message: "login!!!"})
  if(bcrypt.compareSync(req.body.password, req.user.password)){
    const token = buildToken(req.user)
    res.status(200).json({message:`${req.user.username} is back!` , token})
  }else{
    next({status: 401, message: "Invalid credentials"})
  }
});

function buildToken(user){
// ??? why ERR 
//   const payload = {
//     subject : user.user_id,
//     role_name: user.role_name,
//     username: user.username
//   }
//   const option = {
//     expiresIn: '1d',
// }
//   return jwt.sign(payload, JWT_SECRET, option)
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

module.exports = router;

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const User = require('../users/users-model');
const makeToken = require('./auth-token-builde')

// TEST OK: http post :9000/api/auth/register username=foo password=1234 role_name='foo'
// TEST OK: http post :9000/api/auth/register username=faa password=1234 role_name=ceo
router.post("/register", validateRoleName, async (req, res, next) => {
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
  // try{
  //   // res.status(201).json("post /api/auth/register")
  //   const {username, password} = req.body
  //   const {role_name} = req
  //   const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS)
  //   const newUser = await User.add({username, password: hash, role_name})
  //   res.status(201).json(newUser)
  // }catch(err){
  //   next(err)
  // }
    // way 2
    const { username, password } = req.body
    const { role_name } = req
    const hash = bcrypt.hashSync(password, 8)
      User.add({ username, password: hash, role_name })
        .then( newUser=>{
          res.status(201).json(newUser)
          // res.status(201).json({
          //   user: newUser.user,
          //   username: newUser.username,
          //   role_name: newUser.role_name
          // })
        } )
        .catch(next)
});

// TEST ERR: http  post  :9000/api/auth/login username=bonnnxxx password=1234
// TEST : http  post  :9000/api/auth/login username=bob password=1234
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
    try{
      // res.status(201).json("post /api/auth/login")
      // const {password} = req.body
      // console.log("data password =", req.user.password)
      // console.log("body password = ", password)
      // const validPassword = bcrypt.compareSync(password, req.user.password)
      const validPassword = bcrypt.compareSync(req.body.password, req.user.password)
      // console.log(validPassword)
      if (validPassword){
        const token = makeToken(req.user)
        return  res.status(201).json({ message: `${req.user.username} is back!`, token, subject: req.user.user_id})
      }else{
        next({ status: 401, message: "Invalid credentials"})
      }
    }catch(err){
      next(err)
    }
});

module.exports = router;

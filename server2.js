//Import dependencies
const express = require('express')
const mysql = require('mysql')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')

//Create connection for mysql database
const sqlConnection = mysql.createConnection({
    user: 'root',
    host: 'localhost',
    port: 3307,
    password: 'root111',
    database: 'mydatabase'
})
//Connecting to mysql database
sqlConnection.connect((err)=>{
    if (err) throw err
    console.log('Database connected')
})

const app = express()

//middleware
app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({extended: false}))

//API routes
app.get('/dashboard', (req, res)=>{
  if(req.cookies.jwt){
    const verify = jwt.verify(req.cookies.jwt,
      'qyywuuwmzow8ajk672928hsuuaomlapwiajaui4783gtoeueee')
    res.render("myhome.ejs", {username:verify.username})
  }
  else{
    res.redirect('/login')
  }
})
app.get('/register', (req, res)=>{
    res.render('mysignup.ejs', {error: ""})
})
app.get('/login', (req, res)=>{
    res.render('mylogin.ejs',  {error: ""})
})
app.get('/logout', (req, res)=>{
  res.cookie("jwt", "", {maxAge: 1})
  res.redirect('/login')
})
app.get('/dashboard/reset_password?', (req, res)=>{
  res.render('resetpassword.ejs', {error: ""})
})
//End Routes

//Send data from html form to our server
app.post('/register', async (req, res)=>{
    try{
      const hash_password = await bcrypt.hash(req.body.password, 10)
      const userid = {
      id: Date.now().toString(10)
    }
  
      sqlConnection.query('SELECT * FROM NEW_USERS WHERE email = ? OR username = ?', 
        [req.body.email, req.body.username], (err, result)=>{
        if(err) throw err
        if(result.length > 0){ 
            const error = `The provided email or username has already been used by existing user!`
            res.render('mysignup.ejs', {error})
           }else{
            const token = jwt.sign({username:req.body.username}, 
              'qyywuuwmzow8ajk672928hsuuaomlapwiajaui4783gtoeueee')
            res.cookie('jwt', token,{
              maxAge: 600000,
              httpOnly: true
            })
          sqlConnection.query('INSERT INTO NEW_USERS VALUES(?,?,?,?,?)',
             [userid.id, req.body.username, req.body.email, hash_password, token],
            (err)=>{
              if(!err){
              res.redirect('/login')
              }
            })
        }
      })
    }catch(e){
      console.log(e)
      res.redirect('/register')
    }
  })

//Login Authentication
app.post('/login',  (req, res)=>{
  sqlConnection.query('select * from NEW_USERS where email = ?',[req.body.email], 
    async (err, result)=>{
    try{
    if(result.length == 1){
      const user = {email:result[0].email, password:result[0].user_password} 
      const isValidPassword = await bcrypt.compare(req.body.password, 
        user.password)
      const username = result[0].username
      const token = result[0].token
      if(isValidPassword){

        res.cookie('jwt', token,{
          maxAge: 600000,
          httpOnly: true
        })

        res.redirect('/dashboard')
      }else{
        const error = "Incorrect password!"
        res.render('mylogin.ejs', {error} )
      }
    }else{
      const error = "The provided email is not registered!"
      res.render('mylogin.ejs', {error})
    }
  }catch(e){
    console.log(e)
  }
})
})

//Reset user password route
app.post('/reset_password', (req, res)=>{

  sqlConnection.query('select user_password from NEW_USERS WHERE username = ?',
    [req.body.username], async(err, result)=>{
    try{
    if(err) throw err
    if(result.length == 1){
    const isValidPassword = await bcrypt.compare(req.body.current_password, 
      result[0].user_password)
    if(isValidPassword){
      // if(req.body.username !== result[0].username){
      //   const error = "Cannot find the provided username!"
      //   res.render('resetpassword.ejs', {error})
      // }
      if(req.body.new_password2 !== req.body.new_password){
        const error = "New passwords do not match!"
        res.render('resetpassword.ejs', {error})
      }else{
        const hashedNewPassword = await bcrypt.hash(req.body.new_password, 10)
sqlConnection.query('UPDATE NEW_USERS SET user_password = ? WHERE username = ?',
          [hashedNewPassword,req.body.username],
          (err)=>{
            if(err) throw err
            res.cookie("jwt", "", {maxAge: 1})
            res.redirect('/login')
          })
      }
    }else{
      const error = "Your current password is invalid!"
        res.render('resetpassword.ejs', {error})
    }
    }
  }catch(e){
    console.log(e)
  }
  })

})

app.listen(4000)


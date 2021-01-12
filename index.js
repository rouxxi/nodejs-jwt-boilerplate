const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');
const connection = require('./database');

const { SERVER_PORT, CLIENT_URL, JWT_SECRET } = process.env;

const app = express();

app.use(
  cors({
    origin: CLIENT_URL,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Your code here!

// Don't write anything below this line!
app.listen(SERVER_PORT, () => {
  console.log(`Server is running on port ${SERVER_PORT}.`);
});

app.post('/register', (req, res)=>{
  const {email, password} =req.body;
  let hash = bcrypt.hashSync(password, 10);
// Store hash in database
  if (email.length < 1 || password.length < 1){
    res.status(400).send('Please specify both email and password')
  //.json({ errorMessage: 'Please specify both email and password' });
  } else {
    connection.query('INSERT INTO user(email, password) VALUES (?,?)',[email, hash], (error , result)=>{
      console.log('email',email,'pw',password,'hash', hash);
      if (error){
        console.log(error)
        res.status(500).send(`Can't acces to the data. Bad request !`).end();
      }else{
        console.log('pas error')

        res.status(201).send({
          id: result.insertId,
          email: email,
          password: 'hidden',
        }).end();   
      }
      })
  }

})
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res
      .status(400)
      .json({ errorMessage: 'Please specify both email and password' });
  } else {
    connection.query(
      `SELECT * FROM user WHERE email=?`,
      [email],
      (error, result) => {
        if (error) {
          res.status(500).json({ errorMessage: error.message });
        } else if (result.length === 0) {
          res.status(403).json({ errorMessage: 'Invalid email' });
        } else if (bcrypt.compareSync(password, result[0].password)) {
          // Passwords match
          const user = {
            id: result[0].id,
            email,
            password: 'hidden',
          };
          const token = jwt.sign({ id: user.id }, JWT_SECRET, {
            expiresIn: '1h',
          });
          res.status(200).json({ user, token });
        } else {
          // Passwords don't match
          res.status(403).json({ errorMessage: 'Invalid password' });
        }
      }
    );
  }
});

const authenticateWithJsonWebToken = (req, res, next) => {
  if (req.headers.authorization !== undefined) {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err) => {
      if (err) {
        res
          .status(401)
          .json({ errorMessage: "you're not allowed to access these data" });
      } else {
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ errorMessage: "you're not allowed to access these data" });
  }
};


app.get('/users', authenticateWithJsonWebToken,(req, res)=>{
  connection.query('SELECT * FROM user', (error, result)=>{
    if (error){
      res.status(500).send('Bad request');
    } else {
      const rere = result.map((el)=>{
                return {...el, passord : 'hidden'}
      })
      res.status(200).json(rere);
    }
  })
})
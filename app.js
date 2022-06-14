//using dotenv package in this project
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');

const jwt = require('jsonwebtoken'); //create authorized user
const bcrypt = require('bcrypt'); //hash passwords

const cors = require('cors');
const mysql = require('mysql2/promise');
const app = express();


const port = process.env.PORT || 3000;

app.use(express.json());

const pool = mysql.createPool({ //using createPool instead of createConnection
    host: 'localhost', 
    user: 'root', 
    password: 'password', 
    database: 'bvt_demo', 
});

//all the use function are middleware and get called before the endpoint of the API is hit
//created connection with the database 
app.use(async (req, res, next) => {
  try {

    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    await req.db.query('Set SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();
  } catch (err){
    console.log(err);
    if(req.db) req.db.release();
    throw err;
  }
});

app.use(cors());

app.use(bodyParser.json());

//get routes using express
app.get('/user', async (req, res) => { // this route was used to test the database connection
  console.log('Grabbing current user');
  try {
    const user = {
      name: 'Test Subject',
      userName: 'TestingCode53',
      age: 23
    }
    res.json(user);
  } catch(err) {
    console.log('Error in this route', err);
  }
});

//public endpoint for this API 
app.post('/registeruser', async(req, res)=> { //creates new user
  try {
    let user; //initialize user variable
    
    //using bcrypt package to hash the passwords
    await bcrypt.hash(req.body.Passcode, 10).then(async hash => {
      try {
        [user] = await req.db.query(`INSERT INTO user (LastName, FirstName, UserName, Passcode) VALUES (:LastName, :FirstName, :UserName, :Passcode);`,
        {
          LastName: req.body.LastName,
          FirstName: req.body.FirstName,
          UserName: req.body.UserName,
          Passcode: hash
        });

        console.log('user', user);
      } catch(err){
        console.log('error', err);
      }
    });
    //creating authorized user using JWT package
    const authorizedUser = jwt.sign(
      {
        userId: user.insertId,
        ...req.body //using spread object method after inserting the user ID
      },
      process.env.JWT_KEY
    );
    res.json(authorizedUser); //will show the authorize user credentials on screen
  } catch(error){
    console.log('error', error);
  }
});

//authorizing user route
app.post('/authorized', async(req, res)=> {
  try { //checking to make sure there is a valid username from the database
    const [[user]] = await req.db.query(`SELECT * FROM user WHERE UserName= :UserName`,
    {
      UserName: req.body.UserName
    });

    if(!user){
      res.json('Username not found');
    }
    console.log('user:', user);

    const userPasscode = `${user.Passcode}`;

    console.log('User password:', userPasscode);

    //comparing the passcodes in this variable
    const comparePasscodes = await bcrypt.compare(req.body.Passcode, userPasscode);

    if(comparePasscodes){
      const loadUser = {
        userId: user.Id,
        UserName: user.UserName,
        FirstName: user.FirstName,
        LastName: user.LastName
      }

      const authorizedUser = jwt.sign(loadUser, process.env.JWT_KEY);
      console.log('Authorized user');
      res.json(authorizedUser);
    } else {
      res.json('Password not found');
    }
  } catch(err){
    console.log('Error in authorized route', err);
  }
});

//Using JWT to check if there is an authorized header that contains a valid jwt 
app.use(async (req,res,next)=> {
  if(!req.headers.authorization) {
    throw(401, 'Invalid authorization');
  }

  const [scheme, token] = req.headers.authorization.split(' ');

  console.log('[scheme, token]', scheme, ' ', token);

  if(scheme !== 'Bearer'){
    throw(401, 'Invalid authorization');
  }

  try {
    const loadUser = jwt.verify(token, process.env.JWT_KEY);
    console.log('Loading', loadUser);
    
    req.user = loadUser;
  } catch(err){
    if(err.message && (err.message.toUpperCase()=== 'INVALID TOKEN' || err.message.toUpperCase() === 'JWT EXPIRED')) {
      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {
      throw((err.status || 500), err.message);
    }
    console.log(err);
  }

  await next();
});

//These are the private endpoints and they get called after the middleware is ran
app.get('/user-car', async (req, res) => {
  try {
    const [cars] = await req.db.query(
      `SELECT * FROM car WHERE user_id = :user_id`,
      {
        user_id: req.user.user_id
      }
    )
    res.json(cars);

  console.log('/user-car', cars)
  } catch(err) {
    console.log('error in route', err);
  }

});

app.get('/:id', async (req, res) => {
  try {
    const [[cars]] = await req.db.query(
      `SELECT model FROM car WHERE ID = :ID`,
      {
        ID: req.params.ID
      }
    );
  
    res.json(cars);
  }catch(err){
    console.log(err);
  } 
});


app.post('/', async (req, res) => {
  try {
    const cars = await req.db.query(
      `INSERT INTO car (
        Make_id, 
        Make,
        ) VALUES (
          :Make_id,
          :Make,
        )`,
      {
        Make_id: req.body.Make_id,
        Make: req.body.Make
      }
    );
    
    res.json(cars)
  } catch (err) {
    console.log('post /', err)
  }
});

app.put('/:id', async (req, res) => {
  try {
    const [cars] = await req.db.query(`
    UPDATE car SET Make = :Make WHERE ID = :ID
  `, {
    Make: req.body.Make,
    ID: req.params.ID
  });

  res.json(cars);
  }catch(err){
    console.log(err);
  } 
})

app.delete('/:id', async (req, res) => {
  try {
    const [cars] = await req.db.query(`
    DELETE FROM car WHERE ID = :ID
  `, {
    ID: req.params.ID
  });

  res.json(cars);
  }catch(err){
    console.log(err);
  }
})

//starts backend server 
app.listen(port, () => { 
  console.log(`Example app listening at http://localhost:${port}`);
});


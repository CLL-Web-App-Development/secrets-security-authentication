//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));

app.set('view engine', 'ejs');

// Connect to mongodb through mongoose
mongoose.connect('mongodb://localhost:27017/usersDB', {useNewUrlParser:true, useUnifiedTopology:true});


// Schema for the User model
const UserSchema = new mongoose.Schema({
  username: String,
  password: String
});


// Add password encryption capability to the Schema as a plugin. Should be before the creation of a data model out of UserSchema.
UserSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

// User model which would be mapped to the "users" collection in mongodb. User credentials would be instances of this model, mapped to documents
// in "users" collection. The added plugin would automatically encrypt the value stored in password attribute, when an instance of this model is
// created with real data.
const User = new mongoose.model('User', UserSchema);


// GET request handler for home page, for users to register/login
app.get('/', function(req, res){
  res.render('home');
});


// GET request handler to render the user registration page
app.get('/register', function(req, res){
  res.render('register');
});


// GET request handler to render the user login page
app.get('/login', function(req, res){
  res.render('login');
})


// POST request handler to add user registration details to mongodb backend
app.post('/register', function(req, res){

  // Instance of User model, which would be a document in "users" collection within mongodb, when saved.
  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });

  newUser.save(function(err){ // Password encryption happens automatically with the save operation
    if(err){
      res.send('There was an error completing your registration !');
    }
    else{
      res.render('secrets');
    }
  });

});


// POST request handler to login a user processing the input credentials
app.post('/login', function(req, res){

  User.findOne({username: req.body.username}, function(err, matchingUserEntry){ // Password decryption happens automatically with the findOne operation

    if(err){
      res.send('There was an error in processing your login request !');
    }
    else{
      if(matchingUserEntry.password === req.body.password){
        res.render('secrets');
      }
      else{
        res.send('Incorrect password ! Try again !');
      }
    }

  });

});



app.listen(3000, function(){
  console.log('Secrets app server ready for requests !');
});

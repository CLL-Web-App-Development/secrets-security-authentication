//jshint esversion:6
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(session({
  secret: 'Login session secret',
  resave: false,
  saveUninitialized: false
}));

// Its important that passport is initialized and set for session management after the express-session is configured above
app.use(passport.initialize());
app.use(passport.session());

// Connect to mongodb through mongoose
mongoose.connect('mongodb://localhost:27017/usersDB', {useNewUrlParser:true, useUnifiedTopology:true});


// Schema for the User model
const UserSchema = new mongoose.Schema({
  username: String,
  password: String
});

UserSchema.plugin(passportLocalMongoose); // Add instance of passport-local-mongoose as plugin which has strategies to manage session authentication.
                                          // Since it is being added to the schema, session management would be possible with direct access to user
                                          // data, with an instance of model created below.

// User model which would be mapped to the "users" collection in mongodb. User credentials would be instances of this model, mapped to documents
// in "users" collection. The added plugin would automatically encrypt the value stored in password attribute, when an instance of this model is
// created with real data.
const User = new mongoose.model('User', UserSchema);

// Setting up Passport instance to create a local authentication strategy and to serialize/deserialize user data, as part of authentication.
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

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


app.get('/secrets', function(req, res){
  if(req.isAuthenticated()){
    res.render('secrets');
  }
  else{
    res.redirect('/login'); // session expired and user needs to login again.
  }
})


// GET request handler for logging out a user
app.get('/logout', function(req, res){
  req.logout();

  res.redirect('/'); // redirect to the home page after logout.
});


// POST request handler to add user registration details to mongodb backend
app.post('/register', function(req, res){

  // Use the passportLocalPlugin method register() to to the user registration process and authenticate with appropriate handlers
  // The model would be referenced object, as the passportLocalPlugin has been added to the schema from which the model has been derived.
  User.register({username: req.body.username}, req.body.password, function(err, user){

    if(err){
      console.log(err);
      res.redirect('/register'); // To give user another chance to try and register
    }
    else{

      passport.authenticate('local')(req, res, function(){
        res.redirect('/secrets'); // Control reaches here only if authentication would be successful.
                                  // This is a redirect to '/secrets', to allow automatic redirection if already logged in, with out the need for
                                  // another user login. Since the session is tracked and kept alive until logout or server restart.
      });

    }

  });


});


// POST request handler to login a user processing the input credentials
app.post('/login', function(req, res){

  // User instance with the credentials needed for login
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){ // credentials in "user" applied for login/authentication
    if(err){
      res.redirect('/login');
    }
    else{
      passport.authenticate('local')(req, res, function(){
        res.redirect('/secrets');
      });
    }
  });

});


app.listen(3000, function(){
  console.log('Secrets app server ready for requests !');
});

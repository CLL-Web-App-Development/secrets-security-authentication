//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; // Google strategy for oauth
const FacebookStrategy = require('passport-facebook').Strategy; // Facebook strategy for oauth
const findOrCreate = require('mongoose-findorcreate'); // Would be added as schema plugin to be used by a mongodb model

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
  password: String,
  googleId: String, // required in the schema to tie-up local user login to the Google authenticated user-id (part of returned user-profile data).
                   // Or else, each time the authenticate action is performed by user with active login session (say wandering about different
                   // pages on the site) will create new user document in the database, if this attribute can't be found by the
                   // User.findOrCreate method invocation.
  facebookId: String, // required in the schema to tie-up local user login to the Facebook authenticated user-id (part of returned user-profile data).
                   // Or else, each time the authenticate action is performed by user with active login session (say wandering about different
                   // pages on the site) will create new user document in the database, if this attribute can't be found by the
                   // User.findOrCreate method invocation.
  secret: String
});

UserSchema.plugin(passportLocalMongoose); // Add instance of passport-local-mongoose as plugin which has strategies to manage session authentication.
                                          // Since it is being added to the schema, session management would be possible with direct access to user
                                          // data, with an instance of model created below.
UserSchema.plugin(findOrCreate); // Add the package instance to perform the action of finding and creating a model instance in the database, if it is
                                 // not an existent data entry.

// User model which would be mapped to the "users" collection in mongodb. User credentials would be instances of this model, mapped to documents
// in "users" collection. The added plugin would automatically encrypt the value stored in password attribute, when an instance of this model is
// created with real data.
const User = new mongoose.model('User', UserSchema);

// Setting up Passport instance to create a local authentication strategy and to serialize/deserialize user data, as part of authentication.
passport.use(User.createStrategy());

// Below serialization/deserialization hooks work for all authentication strategies. Implicitly invoked during authentication with respective strategy
// like "local", "google", and other available strategies.
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// GoogleStrategy configuration - used with the get request to route: /auth/google, which returns the user profile data upon successful authentication
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets" // redirect uri registered with this app on Google console
  },
  // Callback that would be invoked after Google authentication done in the get request handler for the route: "/auth/google".
  function(accessToken, refreshToken, profile, cb) { // profile has user profile information given in the scope attribute during
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) { // Creates an entry for the user in the mongodb db collection "users".
      return cb(err, user);
    });
  }
));


// GoogleStrategy configuration - used with the get request to route: /auth/facebook, which returns the user profile data upon successful authentication
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


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


// GET request handler for rendering the secrets page
app.get('/secrets', function(req, res){
  if(req.isAuthenticated()){

   // Find user entries that have the secret attribute set to a non-null string
   User.find({secret: {$ne: null}}, function(err, usersWithSecrets){

    if(err){
      res.send(err);
    }
    else{
      res.render('secrets', {userData: usersWithSecrets});
    }

   });

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


// GET request handler that would pop-up Google OAuth page (through a button action on the web page). Notice that there is no callback with req, res, instances.
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }) // on authentication user profile is the data returned back to this app server
);


// GET request handler for redirect URI: "http://localhost:3000/auth/google/secrets", after successful Google authentication.
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect('/secrets');
});



// GET request handler that would pop-up Google OAuth page (through a button action on the web page). Notice that there is no callback with req, res, instances.
app.get('/auth/facebook',
  passport.authenticate('facebook') // on authentication user profile is the data returned back to this app server
);


// GET request handler for redirect URI: "http://localhost:3000/auth/google/secrets", after successful Google authentication.
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page
    res.redirect('/secrets');
});




// GET request handler to render a page for submitting a secret
app.get('/submit', function(req, res){
  if(req.isAuthenticated()){ // Render page to submit a secret only if authenticated
    res.render('submit');
  }
  else{ // else, redirect to login for user authentication
    res.redirect('/login');
  }
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

// POST request handler for saving submitted secret to mongodb
app.post('/submit', function(req, res){

  console.log(req.user);

  User.findById(req.user._id, function(err, matchedUser){ // Passport package adds authenticated user details to "req".

    if(err){
      res.send(err);
    }
    else{
      matchedUser.secret = req.body.secret; // update the user entry with the secret
      matchedUser.save(function(err){ // save the updated user data to the database.
        if(err){
          res.send(err);
        }
        else{
          res.redirect('/secrets'); // on successful data update redirect to secrets page to see the updated list of secrets
        }
      });
    }

  })

});


app.listen(3000, function(){
  console.log('Secrets app server ready for requests !');
});

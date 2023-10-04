const express = require('express');
const app = express();
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');

app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

const users = []; // In a real app, this should be a database
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find((user) => user.id === id);
  if (!user) {
    return done(null, false);
  }
  done(null, user);
});

passport.use(
  new LocalStrategy(function (username, password, cb) {
    const user = users.find((user) => user.username === username);
    if (!user) {
      return cb(null, false);
    }
    if (user.password !== password) {
      return cb(null, false);
    }
    return cb(null, user);
  })
);

app.set('view engine', 'ejs');
app.set('views', 'views');

app.get('/', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('registration');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

  // Store the user data (in-memory, replace with database)
  users.push({ username, password: hashedPassword });

  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username (replace with database query)
  const user = users.find((u) => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    // Create a session and set a cookie
    req.session.userId = user.username;
    // res.cookie('sessionID', req.sessionID);
    res.redirect('/dashboard');
  } else {
    res.redirect('/');
  }
});

app.get('/dashboard', (req, res) => {
  if (req.session.userId) { // Vérifiez si userId est défini dans la session
    res.render('dashboard', { username: req.session.userId });
  } else {
    res.redirect('/');
  }
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  // res.clearCookie('sessionID');
  res.redirect('/');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

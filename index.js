import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import env from "dotenv";
import pg from "pg";

import session from "express-session";
import passport from "passport";
import {Strategy}  from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import flash from "express-flash"; 

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

app.use(session({
  secret : process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized:false,
  cookie: {
    maxAge: 1000*60 * parseInt(process.env.MAX_AGE),
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

const dbConfig = {
  host: process.env.HOST,
  database: process.env.DATABASE,
  user: process.env.USER,
  password: process.env.PASSWORD,
  port: process.env.PORT,
}

async function generateHash(password) {
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;  
}

async function isUser(email){
  const db = new pg.Client(dbConfig);
  try{
    await db.connect();
    const res = await db.query('SELECT * FROM users where email = $1', [email]);
    return (res.rows.length > 0) ? {status: true, user: res.rows[0]} : {status: false};
  } catch(e){
    console.log(e);
    return {status: false};
  } finally{
    await db.end();
  }
}

async function registerUser(email, password){
  console.log("register users");
  const db = new pg.Client(dbConfig);
  try{
    db.connect();
    let hashedPass = await generateHash(password, saltRounds);
    const result = await db.query("INSERT INTO users (email, password) values ($1, $2) RETURNING *", [email, hashedPass]);
    const newUser = result.rows[0].email;
    return {newUser: newUser, status: true};
    
  } catch(e){
    console.log(e);
    return {status: false, error: e};
  } finally{
    await db.end();
  }
}

async function authenticate(email, userPassword){
  if(!((await isUser(email)).status)) return {status:false, error: "user doesn't exist"};

  const db = new pg.Client(dbConfig);
  try{
    db.connect();
    const dbPassword = (await db.query("SELECT password FROM users where email = $1", [email])).rows[0].password;
    const result = bcrypt.compareSync(userPassword,dbPassword);
    
    return (result) ? {status: result}: {status: result, error: "Wrong Password"};

  } catch(e){
    console.log(e);
    return {status: false, error: e};
  } finally{
    await db.end();
  }

}

app.get("/", (req, res) => {
  if(req.isAuthenticated()) res.redirect("/secrets");
  else res.render("home.ejs");
});

app.get("/login", (req, res) => {
  const error = req.flash('error');
  if(req.isAuthenticated()) res.redirect("/secrets");
  else res.render("login.ejs", {error: error});
});

app.get("/register", (req, res) => {
  if(req.isAuthenticated()) res.redirect("/secrets");
  else res.render("register.ejs");
});

app.get("/secrets", (req,res) => {
  if(req.isAuthenticated()) res.render("secrets.ejs");
  else res.redirect("/login");
})

app.get("/auth/google", passport.authenticate("google", {
    scope:["profile", "email"],
  })
);

app.get("/auth/google/secrets",passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));


app.get("/logout", (req,res)=>{
  req.logout((err) =>{
    if(err) console.log(err);
    res.redirect("/");
  })
})

app.post("/register", async (req, res) => {
  let email = req.body.username;
  let pass = req.body.password;

  if((await isUser(email)).status) {
    res.render("register.ejs", {error: "User already exists"});
  } else {
    const result = await registerUser(email, pass);
    console.log(result.status);
    if(result.status){
      req.login(result.newUser, (err) => {
        if(err) {
          console.log(err);
          res.render('register.ejs', { error: 'Registration failed' });
        } else{
          res.redirect("/secrets");
        }
      })
    } else{
      res.render( "register.ejs", {error: result.error});
    }
  }
});



app.post("/login",passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login',
  failureFlash: true,
}));

passport.use("local", new Strategy(async function (username, password, done) {
  console.log(username);
  const result = await authenticate(username, password);

  if (result.status) {
    return done(null, username);
  } else {
    return done(null, false, { message: result.error });
  }
}));

passport.serializeUser((username, done) => {
  done(null, username);
});

passport.deserializeUser(async (username, done) => {
  done(null, username);
});


passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  }, async (accessToken, refreshToken, profile, done) => {
    console.log(profile);
    try{
      const User = await isUser(profile.email);
      if(User.status) {
        done(null, User.user);
      } else{
        const result = await registerUser(profile.email, Date.now().toPrecision() + '' + Math.round(Math.random()*999999));
        if(result.status){
          done(null, result.newUser);
        }else{
          return done(null, false, { message: result.error });
        }
      }
    } catch(e){
      done(e);
    }
  })
);


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

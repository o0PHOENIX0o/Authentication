import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());


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
  console.log("checking users");
  const db = new pg.Client(dbConfig);
  try{
    await db.connect();
    const res = await db.query('SELECT * FROM users where email = $1', [email]);
    console.log(res.rows, res.rows.length);
    return res.rows.length > 0;

  } catch(e){
    console.log(e);
    return false;
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
    console.log(hashedPass);
    await db.query("INSERT INTO users (email, password) values ($1, $2)", [email, hashedPass]);
    return {status: true};
    
  } catch(e){
    console.log(e);
    return {status: false, error: e};
  } finally{
    await db.end();
  }
}

async function authenticate(email, userPassword){
  if(!(await isUser(email))) return {status:false, error: "user doesn't exist"};

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
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});


app.post("/register", async (req, res) => {
  let email = req.body.username;
  let pass = req.body.password;

  console.log(pass);

  if(await isUser(email)) {
    res.render("register.ejs", {error: "User already exists"});
  } else {
    const result = await registerUser(email, pass);
    console.log(result);
    if(result.status){
      res.render("login.ejs");
    } else{
      res.render( "register.ejs", {error: result.error});
    }
  }
});



app.post("/login",async (req,res) => {
  const username = req.body.username;
  const password = req.body.password;
  const result = await authenticate(username, password);
  console.log("login result -> ",result);

  if (result.status) {
    res.render('secrets.ejs');
  } else {
    res.render('login.ejs', { message: result.error });
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

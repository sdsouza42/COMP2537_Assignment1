require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const app = express();
const Joi = require("joi");
const saltRounds = 6;

const port = process.env.PORT || 8008;

const expireTime = 60 * 60 * 1000; //expires after 1 hour  ( minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
	collectionName: 'session',
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

//homepage
app.get('/', (req, res) => {
	let html;
	if (req.session.authenticated) {
	  html = `
		Hello, ${req.session.name}
		<a href="/members"><button>Members Area</button></a>
		<a href="/logout"><button>Logout</button></a>
	  `;
	} else {
	  html = `
		<a href="/login"><button>Login</button></a>
		<a href="/signup"><button>Sign Up</button></a>
	  `;
	}
	res.send(html);
  });
  

//login
app.get('/login', (req, res) => {
	const showError = req.query.error === '1';
	const errorMessage = showError ? '<p>Incorrect email or password.</p>' : '';
	
	const html = `
	  log in
	  ${errorMessage}
	  <form action='/loggingin' method='post'>
		<input name='email' type='email' placeholder='email'>
		<input name='password' type='password' placeholder='password'>
		<button>Submit</button>
	  </form>
	`;
	res.send(html);
  });
  

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect('/login?error=1');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
		req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;
		console.log("Session info:", req.session);


		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect('/login?error=1');
		return;
	}
});


// User signup added verfication for empty fields
app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
	<input name='name' type='text' placeholder='name'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

//JOI check

app.post('/submitUser', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;
	var name = req.body.name;

	const schema = Joi.object(
	{
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required(),
		name: Joi.string().alphanum().max(20).required()
	});
	

	const validationResult = schema.validate({email, password, name}, {abortEarly: false});
	if (validationResult.error != null) {
		const errors = validationResult.error.details.map(detail => detail.message);
		const errorMsg = errors.join('<br>');
		res.send(`<p>${errorMsg}</p><a href="/signup">Go back to sign up</a>`);
		return;
	}
	

	var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({email: email, password: hashedPassword, name: name});
	console.log("Inserted user");

	req.session.authenticated = true;
	req.session.name = name;
	req.session.cookie.maxAge = expireTime;

	res.redirect('/members');
});

//logout
app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});

// Members page
app.get('/members', (req, res) => {
	if (req.session.authenticated) {
	  const randomImageNumber = Math.floor(Math.random() * 3) + 1;
	  const html = `
		Hello, ${req.session.name}<br>
		<a href="/logout"><button>Logout</button></a><br>
		<img src="/image${randomImageNumber}.jpg" alt="Random Image" style="width: 250px;">
	  `;
	  res.send(html);
	} else {
	  res.redirect('/');
	}
  });
  

app.use(express.static(__dirname + "/public"));

// 404
app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
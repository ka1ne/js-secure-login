var express = require('express')
var session = require('express-session');
var mysql = require('mysql')
var bodyParser = require('body-parser');
var fs = require('fs')
var https = require('https')
var app = express()

require('dotenv').config()

var connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

const path = require('path');

app.use(session({
    secret: process.env.SALT,
    resave: true,
    saveUninitialized: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'login.html')))

app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')))

app.post('/reg', function (request, response) {
    var username = request.body.username;
    var password = request.body.password;
    
    var sql = 'SELECT * FROM accounts WHERE username = ? AND password = ?';
    var inserts = [username, password];
    sql = mysql.format(sql, inserts);


});

app.post('/auth', function (request, response) {
    var username = request.body.username;
    var password = request.body.password;

    var sql = 'SELECT * FROM accounts WHERE username = ? AND password = ?';
    var inserts = [username, password];
    sql = mysql.format(sql, inserts);

    if (username && password) {
        connection.query(sql, function (error, results, fields) {
            if (results.length > 0) {
                request.session.loggedin = true;
                request.session.username = username;
                response.redirect('/home');
            } else {
                response.send('Incorrect Username and/or Password!');
            }
            response.end();
        });
    } else {
        response.send('Please enter Username and Password!');
        response.end();
    }
});

app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('Welcome back, ' + request.session.username + '!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
}, app)
    .listen(3000, function () {
        console.log('App listening on port 3000! Go to https://localhost:3000/')
    })
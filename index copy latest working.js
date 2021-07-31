var express = require('express')
var session = require('express-session');
var mysql = require('mysql2')
var bodyParser = require('body-parser');
var fs = require('fs')
var https = require('https')
var app = express()
var bcrypt = require('bcrypt');

require('dotenv').config()

var connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

const rounds = 12;

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

app.post('/reg', async (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    let repeatpass = request.body.repeatpass;

    if (password === repeatpass) {
        try {
            var hashpass = await bcrypt.hash(password, rounds)
        } catch (error) {
            console.log(error)
        }
    }

    let email = request.body.email;

    let sql = 'SELECT email FROM accounts WHERE email = ?';
    let inserts = [email];
    sql = mysql.format(sql, inserts);

    if (email && username && (password === repeatpass)) {
        connection.query(sql, function (error, results, fields) {
            if (results.length > 0) {
                response.send('That email is already registered!');
            } else {
                let sql = 'SELECT username FROM accounts WHERE username = ?';
                let inserts = [username];
                sql = mysql.format(sql, inserts);
                connection.query(sql, function (error, results, fields) {
                    if (results.length > 0) {
                        response.send('That username is already registered!');
                    } else {
                        let sql = 'INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)';
                        let inserts = [username, hashpass, email];
                        sql = mysql.format(sql, inserts);
                        connection.query(sql, function (error, results, fields) {
                            response.send('Registered successfully! <a href="/">Login</a>');
                        })
                    }
                })
            }
        })
    }
});

app.post('/auth', async (request, response) => {
    let username = request.body.username;
    var password = request.body.password;

    try {
        var hashpass = await bcrypt.hash(password, rounds)
    } catch (error) {
        console.log(error)
    }

    let sql = 'SELECT * FROM accounts WHERE username = ?';
    let inserts = [username];
    sql = mysql.format(sql, inserts);

    if (username && hashpass) {
        connection.query(sql, async (error, results, fields) => {
            if (results.length > 0) {
                try {
                    await bcrypt.compare(password, results[0].password, function(err, result) {
                        if (result) {
                            request.session.loggedin = true;
                            request.session.username = username;
                            response.redirect('/home');
                        }
                    });
                    } catch (error) {
                        console.log(error)
                    }
            } else {
                response.send('Incorrect Username and/or Password!');
            }
        });
    } else {
        response.send('Please enter Username and Password!');
    }
});

app.get('/home', function (request, response) {
    if (request.session.loggedin) {
        response.send('Welcome back, ' + request.session.username + '!');
    } else {
        response.send('Please login to view this page!');
    }
});

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
}, app)
    .listen(3000, function () {
        console.log('App listening on port 3000! Go to https://localhost:3000/')
    })


    /**
     * if (results.length > 0) {
                response.send(results);
                await bcrypt.compare(password, results[2], function (error, result) {
                    if (result == true) {
                        request.session.loggedin = true;
                        request.session.username = username;
                        response.redirect('/home');
                    }
                })
            } 
    */
const express = require('express')
const session = require('express-session')
const mysql = require('mysql2')
const bodyParser = require('body-parser')
const fs = require('fs')
const https = require('https')
const bcrypt = require('bcrypt')
const request = require('request')
const csrf = require('csurf')
const { check } = require('express-validator')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode');

require('dotenv').config()

var connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

const rounds = 12;

const path = require('path');

var csrfProtect = csrf({ cookie: false });

const app = express()
app.use(session({
    secret: process.env.SALT,
    resave: true,
    saveUninitialized: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(csrf());

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

app.get('/passchange.html', (req, res) => res.sendFile(path.join(__dirname, 'passchange.html')));

app.get('/token', csrfProtect, (req, res) => res.json({ csrfToken: req.csrfToken() }));

app.post('/reg', [
    check('username').isLength({ min: 3 }).trim().escape(),
    check('email').isEmail().normalizeEmail()
], csrfProtect, async (req, res) => {

    if (req.body['g-recaptcha-response'] === undefined || req.body['g-recaptcha-response'] === '' || req.body['g-recaptcha-response'] === null) {
        return res.json({ "responseCode": 1, "responseDesc": "Please select captcha" });
    }

    var secretKey = process.env.KEY;

    var verificationUrl = "https://www.google.com/recaptcha/api/siteverify?secret=" + secretKey + "&response=" + req.body['g-recaptcha-response'] + "&remoteip=" + req.connection.remoteAddress;

    request(verificationUrl, async (error, response, body) => {
        body = JSON.parse(body);

        if (body.success !== undefined && !body.success) {
            return res.json({ "responseCode": 1, "responseDesc": "Failed captcha verification" });
        }

        let username = req.body.username;
        let password = req.body.password;
        let repeatpass = req.body.repeatpass;

        if (password === repeatpass) {
            try {
                var hashpass = await bcrypt.hash(password, rounds)
            } catch (error) {
                console.log(error)
            }
        }

        let email = req.body.email;

        let sql = 'SELECT email FROM accounts WHERE email = ?';
        let inserts = [email];
        sql = mysql.format(sql, inserts);

        if (email && username && (password === repeatpass)) {
            connection.query(sql, function (error, results, fields) {
                if (results.length > 0) {
                    res.send('That email is already registered!');
                } else {
                    let sql = 'SELECT username FROM accounts WHERE username = ?';
                    let inserts = [username];
                    sql = mysql.format(sql, inserts);
                    connection.query(sql, function (error, results, fields) {
                        if (results.length > 0) {
                            res.send('That username is already registered!');
                        } else {
                            let sql = 'INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)';
                            let inserts = [username, hashpass, email];
                            sql = mysql.format(sql, inserts);
                            connection.query(sql, function (error, results, fields) {
                                res.send('Registered successfully! <a href="/">Login</a>');
                            })
                        }
                    })
                }
            })
        }
    });
});

app.post('/pass', csrfProtect, async (req, res) => {
    var currPass = req.body.currPass;
    var password = req.body.password;

    try {
        var hashpass = await bcrypt.hash(password, rounds)
    } catch (error) {
        console.log(error)
    }

    let sql = 'SELECT * FROM accounts WHERE username = ?';
    let inserts = [req.session.username];
    sql = mysql.format(sql, inserts);

    if (hashpass) {
        connection.query(sql, async (error, results, fields) => {
            if (results.length > 0) {
                await bcrypt.compare(currPass, results[0].password, function (err, result) {
                    let sql = 'UPDATE accounts SET password = ? WHERE username = ?';
                    let inserts = [hashpass, req.session.username];
                    sql = mysql.format(sql, inserts);
                    connection.query(sql, function (error, results, fields) {
                        res.send('Password changed! Re-login <a href="/">Login</a>');
                    })
                });
            }
        })
    }
});

app.post('/auth', [
    check('username').isLength({ min: 3 }).trim().escape(),
    check('code').isNumeric().escape()
], csrfProtect, async (request, response) => {
    let username = request.body.username;
    var password = request.body.password;
    var code = request.body.code;

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
                if (results[0].secret) {
                    var secret = results[0].secret;
                    if (speakeasy.totp.verify({
                        secret: secret,
                        encoding: 'base32',
                        token: code
                    })) {
                        try {
                            await bcrypt.compare(password, results[0].password, function (err, result) {
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
                        response.send('Code is wrong!')
                    }
                } else {
                    try {
                        await bcrypt.compare(password, results[0].password, function (err, result) {
                            if (result) {
                                request.session.loggedin = true;
                                request.session.username = username;
                                response.redirect('/home');
                            }
                        });
                    } catch (error) {
                        console.log(error)
                    }
                }
            } else {
                response.send('Incorrect Username and/or Password!');
            }
        });
    } else {
        response.send('Please enter Username and Password!');
    }
});

app.get('/2fa', csrfProtect, (req, res) => {
    var secret = speakeasy.generateSecret({ length: 20 });

    let sql = 'SELECT username FROM accounts WHERE username = ?';
    let inserts = [req.session.username];
    sql = mysql.format(sql, inserts);

    connection.query(sql, function (error, results, fields) {
        if (results.length > 0) {
            let sql = 'UPDATE accounts SET secret = ? WHERE username = ?';
            let inserts = [secret.base32, req.session.username];
            sql = mysql.format(sql, inserts);

            connection.query(sql, function (error, results, fields) {
                QRCode.toDataURL(secret.otpauth_url, function (err, image_data) {
                    res.send('<img src="' + image_data + '" alt="QRCode">')
                });
            })
        }
    })
});

app.get('/home', function (request, response) {
    if (request.session.loggedin) {
        response.send('Welcome back, ' + request.session.username + '!'
            + '<form action="/passchange.html" style="margin-top: 2vh;"><input type="submit" value="Change Password"/></form>'
            + '<form action="/2fa" style="margin-top: 2vh;"><input type="submit" value="2FA"/></form>');
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
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const asyncHandler = require("express-async-handler");
const { body, validationResult, customSanitizer } = require("express-validator"); 
const passportJWT = require('passport-jwt');
const jwt = require("jsonwebtoken");
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const jwt_decode = require("jwt-decode");
const mongoose = require("mongoose");
mongoose.set("strictQuery", false);
require('dotenv').config();
const dev_db_url = process.env.MONGOURL;
const mongoDB = process.env.MONGODB_URI || dev_db_url;
const marketstack = process.env.MARKETSTACK
const helmet = require("helmet");
const RateLimit = require("express-rate-limit");
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const cors = require('cors');
const fetch = (...args) =>
	import('node-fetch').then(({default: fetch}) => fetch(...args));

const User = require("./models/user");
const Stock = require("./models/stock");
const Account = require("./models/account");
const Portfolio = require("./models/portfolio");
const Position = require('./models/position');

mongoose.connect(mongoDB, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      "script-src": ["'self'", "code.jquery.com", "cdn.jsdelivr.net"],
      "img-src": ["'self'", "https: data:"]
    },
  })
)

app.use(cors());
app.use(passport.initialize());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

passport.use(new LocalStrategy(
  async(username, password, done) => {
    try {
      const user = await User.findOne({ username: username }).exec();
      if (!user) {
        return done(null, false, { message: "Incorrect username"});
      } else {
        bcrypt.compare(password, user.password, (err, res) => {
          if (res === true) {
            return done(null, user)
          } else {
            return done(null, false, { message: "Incorrect password"})
          }
        })
      }
    }
    catch(err) {
      return done(err)
    }
  }));

  passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET,
  },
  async(jwt_payload, done) => {
    console.log(jwt_payload);
    const user = await User.findById(jwt_payload.user._id).exec();
    if (user) {
        return done(null, user);
    } 
    else {
        return done(null, false);
    }
  }));

  //implement error message of duplicate username in front end if 500 server error is sent 
  app.post('/signup', upload.any(), [
    body("username", 'Username must not be empty')
    .trim()
    .isLength({ min: 1 })
    .escape(),
    body("password", "Password must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
    body('passwordConfirmation').custom((value, { req }) => {
      return value === req.body.password;
    })
    .withMessage('Passwords must match'),
    asyncHandler(async(req, res, next) => {
  
      const errors = validationResult(req);
  
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });
  
      if (!errors.isEmpty()) {
        return res.json({
          user: user,
          errors: errors.array(),
        });
      } else {
        let salt = bcrypt.genSaltSync(10);
        let hash = bcrypt.hashSync(req.body.password, salt);
        user.password = hash;
        await user.save();
        const account = new Account({
          balance: 0,
          user: user._id
        });
        await account.save();
        const portfolio = new Portfolio({
          user: user._id
        });
        await portfolio.save();
        res.json(user);
      }
    })
  ])

  app.post("/login", upload.any(), async(req, res, next) => {
    passport.authenticate(
      'local', {session: false}, async(err, user, info) => {
        if (!user || err) {
          return res.status(404).json({message: "Incorrect username or password", status: 404})
        } else {
          const opts = {};
          const secret = process.env.SECRET;
          const authuser = await User.findOne({ username: req.body.username }).exec();
  
              const body = { _id: authuser._id, username: authuser.username };
              const token = jwt.sign({ user: body }, secret);
              if (typeof window !== 'undefined') {
              localStorage.setItem("jwt", JSON.stringify(token));
              }
              return res.json({ token });
        }
      }
    ) (req, res, next)}
  );

  

  //Get latest data on a particular stock, updatable every 15 minutes
  app.get('/stocks/:stockid/latestdata', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
    const url = `https://api.marketstack.com/v1/tickers/${req.params.stockid}/intraday/latest?access_key=${marketstack}&interval=15min`;
    const response = await fetch(url);
    const data = await response.json();

    if (data.error) {
      res.status(404).json({message: "Invalid symblol", status: 404})
    } else {
    res.json(data);
  }
  }))

  //Get information on stock ticker
  app.get('/stocks/:stockid/info', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
    const url = `https://api.marketstack.com/v1/tickers/${req.params.stockid}?access_key=${marketstack}`;
    const response = await fetch(url);
    const data = await response.json();

    if (data.error) {
      res.status(404).json({message: "Invalid symblol", status: 404})
    } else {
    res.json(data);
  }
  }));

app.get('/stocks/:stockid/:interval', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
  const currDate = new Date();
  const currDateNum = currDate.getTime();
  const firstDate = req.params.interval;
  const dayMilliSec = 1*24*60*60*1000
  const firstDateNum = firstDate*dayMilliSec;
  const firstDateCalc = currDateNum - firstDateNum;
  const dateFrom = new Date(firstDateCalc);
  const dateFromfmt = dateFrom.toISOString().slice(0, -5);
  const dateFromfnl = dateFromfmt.replace('T', ' ');
  const dateTofmt = currDate.toISOString().slice(0, -5);
  const dateTofnl = dateTofmt.replace('T', ' ')
  const url = `https://api.marketstack.com/v1/eod?access_key=${marketstack}&symbols=${req.params.stockid}&date_from=${dateFromfnl}&date_to=${dateTofnl}`
  const response = await fetch(url);
  const data = await response.json();

  if (data.error) {
    res.status(404).json(data.error)
  } else {
    const stockinfo = data.data;
    res.json(stockinfo)
  }
}));

app.put('/account/:userid', upload.any(), passport.authenticate('jwt',  {session: false}), [
  body("amount")
  .trim()
  .isInt({min: 0, max: 5000})
  .withMessage("Movement of funds are limited to amounts between $0 and $5000"),

  asyncHandler(async(req, res, next) => {
    const errors = validationResult(req);

    const account = await Account.findOne({user: req.params.userid}).exec();

    if (!errors.isEmpty()) {
      res.json({
        errors: errors.array(),
      });
      return;
    } else {
      if (account.user.toString() === req.params.userid) {
      let balance = account.balance;
      let amount = req.body.amount;
      let action = req.body.action;

      if (action === 'add') {
        let total = balance + amount;
        let updatedacc = await Account.findByIdAndUpdate(account._id, { balance: total});
        res.json(updatedacc);
      } 
      if (action === 'withdraw') {
        let total = balance - amount;
        if (total < 0) {
          res.status(403).json({message: "Cannot withdraw more than balance in account", status: 403})
        } else {
          let updatedacc = await Account.findByIdAndUpdate(account._id, { balance: total});
          res.json(updatedacc);
        }
      }
    } else {
      res.status(401).json({message: 'Unauthorized to access this account', status: 401})
    }
    }
    
  })
]);

app.put('/portfolio/:stockid', upload.any(), passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
  let quantity = req.body.quantity;
  let ticker = req.params.stockid;
  let price = req.body.price;
  let action = req.body.action;
  let userid = req.body.userid;

  const account = await Account.findOne({user: userid}).exec();

  let total = quantity*price;
  let balance = account.balance;
  res.json(balance);

  if (action === 'buy') {
  
  if (position === null) {
    if (total <= balance) {
    let newpos = new Position({
      ticker: ticker,
      quantity: quantity,
      value: total,
      realized: 0,
    })
    let uptbal = balance - total;
    const portfolio = await Portfolio.findOneAndUpdate({user: userid}, {$push: {positions: newpos}})
    const updacc = await Account.findOneAndUpdate({user: userid}, {$set: {balance: uptbal}});
    res.json(portfolio)
  }
  if (total > balance) {
    res.status(403).json({message: 'Attempted purchase more than balance in account', status: 403});
  }
  }
  else {
    if (total <= balance) {
      let currqnt = position.quantity;
      let updqnt = currqnt + quantity;
      let currval = position.value;
      let updval = total + currval;
      let uptbal = balance - total;

      const updpos = await Position.findOneAndUpdate({ticker: ticker}, {$set: {quantity: updqnt, value: updval}});
      const updacc = await Account.findOneAndUpdate({user: userid}, {$set: {balance: uptbal}});
      res.json(updpos);
    }
    if (total > balance) {
      res.status(403).json({message: 'Attempted purchase more than balance in account', status: 403});
    }
  }
}

if (action === 'sell') {
  if (quantity <= position.quantity) {
    let currqnt = position.quantity;
    let updqnt = currqnt - quantity;
    let currval = position.value;
    let updval = currval - total; 
    let uptbal = balance + total;
    let nowreal = total - ((currval/currqnt)*quantity);
    let updreal = position.realized + nowreal;
    
    const updpos = await Position.findOneAndUpdate({ticker: ticker}, {$set: {quantity: updqnt, value: updval, realized:updreal}});
    const updacc = await Account.findOneAndUpdate({user: userid}, {$set: {balance: uptbal}});
    res.json(updpos);
  }
  if (quantity > position.quantity) {
    res.status(403).json({message: 'Attempted to sell more shares than owned in account', status: 403});
  } 
}
}));

app.get('/account/:userid', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
  const account = await Account.findOne({user: req.params.userid}).exec();
  
  if (account === null) {
    return res.status(404).json({message: 'Account not found', status: 404})
  }

  res.json(account);
}))

app.get('/position/:stockid/:userid', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
  const position = await Position.findOne({user: req.params.userid, ticker: req.params.stockid}).exec();

  if (position === null) {
    return res.status(404).json({message: 'Position not found', status: 404})
  }

  res.json(position);
}))

app.get('/portfolio/:userid', passport.authenticate('jwt',  {session: false}), asyncHandler(async(req, res, next) => {
  const portfolio = await Portfolio.findOne({user: req.params.userid}).exec();

  if (position === null) {
    return res.status(404).json({message: 'Portfolio not found', status: 404})
  }

  res.json(portfolio);
}))

module.exports = app;

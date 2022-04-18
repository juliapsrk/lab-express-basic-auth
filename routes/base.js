const express = require('express');
const router = new express.Router();
const User = require('./../models/user');
const bcryptjs = require('bcryptjs');
const routeGuard = require('../middleware/route-guard');

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/register', (req, rest, next) => {
  res.render('register');
});

router.post('/register', (req, res, next) => {
  const { username, password } = req.body;

  if (!password || !username) {
    next(new Error ('Cannot be any empty field.'));
    return;
  }

  bcryptjs.hash(password, 10)
  .then((passwordHashAndSalt) => {
    return User.create({ username, passwordHashAndSalt });
  })
  .then((user) => {
    req.session.userId = user._id;
    res.redirect('/');
  })
  .catch((error) => next(error));
});

router.get('/login', (req, res, next) => {
  res.render('login');
});

router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (!password || !username) {
    next(new Error('Cannot be any empty field.'));
    return;
  }

  let user;
  User.findOne({ username })
  .then ((_user) => {
    if (!_user) return Promise.reject(new Error('There is no user with that username.'));

    user = _user;
    return bcryptjs.compare(password, _user.passwordHashAndSalt);
  })
  .then((result) => {
    if (!result) return Promise.reject(new Error('Wrong password.'));

    req.session.userId = user._id;
    req.redirect('/private');
  })
  .catch((error) => next(error));
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

router.get('/main', routeGuard, (req, res, next) => {
  res.render('main');
});

router.get('/profile', routeGuard, (req, res, next) => {
  res.render('profile');
});

router.get('/profile/edit', routeGuard, (req, res, next) => {
  res.render('editProfile');
});

router.post('/profile/edit', (req, res, next) => {
  const { name } = req.body;

  User.findByIdAndUpdate(req.user._id, { name })
    .then(() => {
      res.redirect('/profile');
    })
    .catch((error) => next(error));
});

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;

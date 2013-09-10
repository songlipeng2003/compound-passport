var passport = require('passport');

exports.callback = function (accessToken, refreshToken, profile, done) {
    exports.User.findOrCreate({
        googleId: profile.id,
        profile: profile
    }, function (err, user) {
        done(err, user);
    });
};

exports.init = function (conf, app) {
    var Strategy = require('passport-google-oauth').OAuth2Strategy;
    passport.use(new Strategy({
        clientID: conf.google_oauth.clientID,
        clientSecret: conf.google_oauth.secret,
        callbackURL: conf.baseURL + 'auth/google_oauth/callback'
    }, exports.callback));

    app.get('/auth/google_oauth',
        passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/userinfo.profile', 
            'https://www.googleapis.com/auth/userinfo.email'] }));
    app.get('/auth/google_oauth/callback',
        passport.authenticate('google', { failureRedirect: '/' }),
        exports.redirectOnSuccess);
};
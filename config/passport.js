const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const { pool } = require("./db");

const initialize = (passport) => {
  const authenticateUser = (email, password, done) => {
    pool.query(`SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
      if (err) {
        throw err;
      }

      if (results.rows.length > 0) {
        const user = results.rows[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
            throw err;
          }
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false), { message: "Password is not correct" };
          }
        });
      } else {
        return done(null, false, { message: "Email is not registered" });
      }
    });
  };

  passport.use(
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
      },
      authenticateUser
    )
  );

  // stores user id in the session cookie
  passport.serializeUser((user, done) => done(null, user.id));
  // uses the user id to from session cookie to obtain user details from database and stores into the session cookie
  passport.deserializeUser((id, done) => {
    pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
      if (err) {
        throw err;
      }
      return done(null, results.rows[0]);
    });
  });
};

module.exports = initialize;

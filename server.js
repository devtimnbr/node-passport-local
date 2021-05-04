const express = require("express");
const app = express();
const bycrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");

const { pool } = require("./config/db");
const initializePassport = require("./config/passport");
const { registerValidator } = require("./utils/formValidator");

initializePassport(passport);

const PORT = process.env.PORT || 4000;

// Middlewares
// EJS as rendering engine
app.set("view engine", "ejs");
// sends details from frontend to backend
app.use(express.urlencoded({ extended: false }));
// store user auth details in session
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  })
);
// init passport middleware
app.use(passport.initialize());
app.use(passport.session());
// display flash message (toasts)
app.use(flash());
//Auth middlewares
const checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
};
const checkNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/login");
};

// Routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
  res.render("login");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user.name });
});

app.get("/users/logout", (req, res) => {
  req.logOut();
  req.flash("success_msg", "You have logged out");
  res.redirect("/users/login");
});

app.post("/users/register", async (req, res) => {
  const { name, email, password, password2 } = req.body;

  const errors = registerValidator({ name, email, password, password2 });

  if (errors.length > 0) {
    res.render("register", { errors });
  } else {
    // Form validation has passed
    let hashedPassword = await bycrypt.hash(password, 10);

    // Check if User already exists
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }

        if (results.rows.length > 0) {
          errors.push({ message: "Email already registered" });
          res.render("register", { errors });
        } else {
          // Register the user
          pool.query(
            `INSERT INTO users (name, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

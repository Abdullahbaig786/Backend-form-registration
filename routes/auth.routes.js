// routes/auth.routes.js

const { Router } = require("express");
const router = new Router();
//for bcryption
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");
const mongoose = require("mongoose");

//get
router.get("/signup", (req, res) => res.render("auth/signup"));
//post
router.post("/signup", (req, res, next) => {
  // console.log("The form data: ", req.body);

  const { username, email, password } = req.body;
  //console.log(req.body);

  // validation for exist
  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
    });
    return;
  }
  //making password incrypt
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword,
      });
    })
    //
    .then((userFromDB) => {
      // console.log("Newly created user is: ", userFromDB);
      res.redirect("/userProfile");
    })
    // .catch((error) => next(error));
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else if (error.code === 11000) {
        console.log(
          " Username and email need to be unique. Either username or email is already used. "
        );

        res.status(500).render("auth/signup", {
          errorMessage: "User not found and/or incorrect password.",
        });
      } else {
        next(error);
      }
    }); // close .catch()

  //Password Validation
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render("auth/signup", {
      errorMessage:
        "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
    return;
  }
}); //close post
router.get("/userProfile", (req, res) => {
  res.render("users/user-profile", { userInSession: req.session.currentUser });
});
//////////// L O G I N ///////////
router.get("/login", (req, res) => res.render("auth/login"));
router.post("/login", (req, res, next) => {
  console.log("SESSION =====> ", req.session);
  const { email, password } = req.body;

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }
  //////////// L O G O U T ///////////
  router.post("/logout", (req, res, next) => {
    req.session.destroy((err) => {
      if (err) next(err);
      res.redirect("/");
    });
  });

  //check the user is inside the database or not
  User.findOne({ email })
    .then((user) => {
      if (!user) {
        console.log("Email not registered. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        // res.render("users/user-profile", { user });
        req.session.currentUser = user;
        res.redirect("/userProfile");
      } else {
        console.log("Incorrect password. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
      }
    })
    .catch((error) => next(error));
});

module.exports = router;

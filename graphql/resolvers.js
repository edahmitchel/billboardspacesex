const User = require("../models/user");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = {
  createUser: async function ({ userInput }, req) {
    console.log(userInput.email, userInput.pass, userInput.username);
    const errors = [];
    if (!validator.default.isEmail(userInput.email)) {
      errors.push({ message: "email is invalid" });
    }
    if (validator.default.isEmpty(userInput.pass)) {
      errors.push({ message: "password is invalid" });
    }
    if (validator.default.isEmpty(userInput.username)) {
      errors.push({ message: "username is invalid" });
    }
    if (errors.length > 0) {
      const error = new Error("invalid input");
      console.log(errors);
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const existingUser = await User.findOne({ email: userInput.email });
    if (existingUser) {
      const error = new Error("user already exists");
      throw error;
    }
    const email = userInput.email;
    const username = userInput.username;
    const password = userInput.pass;
    // hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // create a new user document and save it to the database
    const user = new User({
      username,
      email,
      password: hashedPassword,
    });
    const createdUser = await user.save();
    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },
  hello: () => {
    return "Hello world!";
  },
  login: async function ({ email, pass }, req) {
    // retrieve the user from the database by email
    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error("user does not exist");
      error.code = 401;
      throw error;
    }

    // compare the hashed password using bcrypt
    const isMatch = await bcrypt.compare(pass, user.password);
    if (!isMatch) {
      const error = new Error("invalid password");
      error.code = 401;
      throw error;
    }

    // generate a JSON Web Token (JWT)
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);
    return { token: token, user: user };
  },
};

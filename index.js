const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./models/user");
const nodemailer = require("nodemailer");
require("dotenv").config();
const { graphqlHTTP } = require("express-graphql");
const grapqlResolver = require("./graphql/resolvers");
const grapqlSchema = require("./graphql/schema");

const app = express();
app.use(bodyParser.json());
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
  console.log("MongoDB connected!");
});
// password reset
//  Create a transporter to send emails using nodemailer
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Endpoint to initiate password reset by sending a reset link to the user's email
app.post("/reset-password", async (req, res) => {
  try {
    const { email } = req.body;

    // Check if the user with the provided email exists
    const user = await User.findOne({ email });
    if (user) {
      // Generate a reset token using JWT
      const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, {
        expiresIn: "1h", // Set the token to expire in 1 hour
      });
      // Send a password reset email to the user
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset",
        html: `
    <h1>Password Reset</h1>
    <p>Please click the link below to reset your password:</p>
    <a href="${process.env.CLIENT_URL}/reset-password/${resetToken}">${process.env.CLIENT_URL}/reset-password/${resetToken}</a>
  `,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Error sending password reset email: ", error);
          res
            .status(500)
            .json({ error: "Failed to send password reset email" });
        } else {
          console.log("Password reset email sent: ", info.response);
          res
            .status(200)
            .json({ message: "Password reset email sent successfully" });
        }
      });
    } else {
      // If the user does not exist, return an error
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint to render the password reset form
app.get("/reset-password/:token", (req, res) => {
  // Get the reset token from the URL parameters
  const resetToken = req.params.token;

  // Verify the reset token using JWT
  jwt.verify(resetToken, process.env.JWT_SECRET, (error, decoded) => {
    if (error) {
      console.error("Error verifying reset token: ", error);
      res.status(400).json({ error: "Invalid reset token" });
    } else {
      // If the reset token is valid, render the password reset form
      res.send(`
        <html>
          <head>
            <title>Password Reset</title>
            <style>
              body {
                font-family: Arial, sans-serif;
              }
              form {
                max-width: 300px;
                margin: 0 auto;
              }
              input {
                display:              input {
                  display: block;
                  width: 100%;
                  margin-bottom: 10px;
                  padding: 8px;
                  border: 1px solid #ccc;
                }
                button {
                  display: block;
                  width: 100%;
                  padding: 10px;
                  background-color: #007bff;
                  color: #fff;
                  border: none;
                  cursor: pointer;
                }
              </style>
            </head>
            <body>
              <h1>Password Reset</h1>
              <p>Please enter your new password below:</p>
              <form action="/reset-password" method="post">
                <input type="hidden" name="token" value="${resetToken}">
                <input type="password" name="password" placeholder="New Password" required>
                <input type="password" name="confirmPassword" placeholder="Confirm Password" required>
                <button type="submit">Reset Password</button>
              </form>
            </body>
          </html>
        `);
    }
  });
});

// Endpoint to handle password reset form submission
app.post("/reset-password", async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;

    // Verify the reset token using JWT
    jwt.verify(token, process.env.JWT_SECRET, async (error, decoded) => {
      if (error) {
        console.error("Error verifying reset token: ", error);
        res.status(400).json({ error: "Invalid reset token" });
      } else {
        const { email } = decoded;

        // Check if the passwords match
        if (password === confirmPassword) {
          // Hash the new password
          const hashedPassword = await bcrypt.hash(password, 10);

          // Update the user's password in the database
          await User.findOneAndUpdate({ email }, { password: hashedPassword });

          // Send a password reset success message
          res.status(200).json({ message: "Password reset successful" });
        } else {
          // If passwords do not match, return an error
          res.status(400).json({ error: "Passwords do not match" });
        }
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// end
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // create a new user document and save it to the database
    const user = new User({
      username,
      email,
      password: hashedPassword,
    });
    await user.save();

    // return a success message
    res.status(200).json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // retrieve the user from the database by email
    const user = await User.findOne({ email });
    if (user) {
      // compare the hashed password using bcrypt
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        // generate a JSON Web Token (JWT)
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);

        // return the token
        res.status(200).json({ token });
      } else {
        res.status(401).json({ error: "Invalid email or password" });
      }
    } else {
      res.status(401).json({ error: "Invalid email or password" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.use(
  "/graphql",
  graphqlHTTP({
    schema: grapqlSchema,
    rootValue: grapqlResolver,
    graphiql: true,
    customFormatErrorFn(err) {
      if (!err.originalError) {
        return err;
      }
      const data = err.originalError.data;
      const message = err.message || "an error occures";
      const code = err.originalError.code || 500;
      return {
        message: message,
        status: code,
        data: data,
      };
    },
  })
);
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

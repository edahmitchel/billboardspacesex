const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./models/user");
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

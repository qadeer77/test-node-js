// Import required modules
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const redis = require("redis");
const { promisify } = require("util");

// Initialize express app
const app = express();
app.use(express.json());

// Mock database to store user credentials
const users = [];
const failedLogins = new Map();

// Secret key for JWT
const secretKey = "your-secret-key";

// Rate limiting configuration
const userRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: "Too many requests from this IP, please try again later.",
});

// Slow down configuration for failed logins
const loginSpeedLimiter = slowDown({
  windowMs: 5 * 60 * 1000, // 5 minutes
  delayAfter: 5, // After 5 failed attempts
  delayMs: 1000, // Delay 1 second for each subsequent attempt
});

// Redis client
const redisClient = redis.createClient();
const getAsync = promisify(redisClient.get).bind(redisClient);
const setAsync = promisify(redisClient.set).bind(redisClient);

// Sign-up route
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  // Check if username is already taken
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(409).json({ message: "Username already taken" });
  }

  try {
    // Hash the password
    const hash = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = {
      username,
      password: hash,
    };

    // Store user in the database
    users.push(newUser);

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  // Check if IP is blocked
  if (failedLogins.has(ip) && failedLogins.get(ip).attempts >= 5) {
    return res
      .status(403)
      .json({ message: "IP blocked due to excessive failed login attempts" });
  }

  try {
    // Find the user in the database
    const user = users.find((user) => user.username === username);
    if (!user) {
      // Increment failed login attempts for the IP
      incrementFailedLoginAttempts(ip);
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Compare passwords
    const result = await bcrypt.compare(password, user.password);
    if (!result) {
      // Increment failed login attempts for the IP
      incrementFailedLoginAttempts(ip);
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Reset failed login attempts for the IP
    resetFailedLoginAttempts(ip);

    // Generate JWT token
    const token = jwt.sign({ username }, secretKey, { expiresIn: "1h" });

    res.status(200).json({ token });
} catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Protected route
app.get("/protected", (req, res) => {
  const token = req.headers.authorization;

  // Check if token is provided
  if (!token) {
    return res.status(401).json({ message: "Token not provided" });
  }

  try {
    // Verify the token
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
      }

      // Token is valid
      res.status(200).json({ message: "Protected route accessed successfully" });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Helper function to increment failed login attempts for an IP
function incrementFailedLoginAttempts(ip) {
  if (failedLogins.has(ip)) {
    const { attempts } = failedLogins.get(ip);
    failedLogins.set(ip, { attempts: attempts + 1 });
  } else {
    failedLogins.set(ip, { attempts: 1 });
  }
}

// Helper function to reset failed login attempts for an IP
function resetFailedLoginAttempts(ip) {
  failedLogins.delete(ip);
}

// Start the server
app.listen(3000, () => {
  console.log("Server started on port 3000");
});

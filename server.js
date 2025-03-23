import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import fs from 'fs';
import { spawn } from 'child_process'; // Import child_process

import multer from 'multer';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = 5000; // Use port 5000 for everything

// Convert ES module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer storage for single file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // Use timestamp and original name to create a unique filename
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Serve static files from the build folder and current directory
app.use(express.static(path.join(__dirname, 'dist')));
app.use(express.static(__dirname));

// Middleware to parse JSON bodies
app.use(express.json());

// Connect to MongoDB (local)
mongoose.connect(process.env.mongodb_urri || 'mongodb://127.0.0.1:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Connection Error:', err));

// Define User schema and model (with plotContent fields)
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  profileImage: Buffer, // Field to store the image
  plotContent1: String,  // Field to store HTML content from plot1.html
  plotContent2: String,  // Field to store HTML content from plot2.html
  plotContent3: String,  // Field to store HTML content from plot3.html
});
const User = mongoose.model("User", UserSchema);

// -----------------
// Login Endpoint
// -----------------
app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) {
      return res.json({ message: "Please provide email and password." });
    }
    email = email.trim().toLowerCase();
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "User does not exist. Please sign up." });
    }
    if (user.password !== password) {
      return res.json({ message: "Invalid email or password." });
    }
    
    // Write the current user's email to currentUser.txt before sending response
    try {
      fs.writeFileSync(path.join(__dirname, 'currentUser.txt'), user.email);
      console.log("currentUser.txt updated with email:", user.email);
    } catch (err) {
      console.error("Error writing currentUser.txt:", err);
    }
    
    // Create a plain object with only the fields you need
    const userData = { name: user.name, email: user.email };
    res.json({ message: `Welcome back, ${user.name}!`, user: userData });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Error during login." });
  }
});

// Serve the login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    let { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.json({ message: "Please fill out all fields." });
    }
    email = email.trim().toLowerCase();
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ message: "User already exists. Please log in." });
    }
    const newUser = new User({ name, email, password });
    await newUser.save();
    res.json({ message: "Signup successful! You can now log in." });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Error during signup." });
  }
});

// File Upload Endpoints remain unchanged
app.post('/upload-multiple', upload.array('files'), (req, res) => {
  console.log("Received upload request");
  if (!req.files || req.files.length === 0) {
      console.log("No files received");
      return res.status(400).json({ error: 'No files uploaded' });
  }
  console.log("Files uploaded:", req.files);
  res.json({ message: 'Files uploaded successfully', files: req.files });
});

// New: File Upload Endpoint for a single pcapng file
app.post('/upload-file', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded." });
  }
  
  const filePath = req.file.path;
  console.log("File stored at:", filePath);
  
  // Spawn the Python script and pass the file path as argument
  const pythonProcess = spawn('python', ['generate.py', filePath]);
  
  let scriptOutput = "";
  pythonProcess.stdout.on('data', (data) => {
    scriptOutput += data.toString();
  });
  pythonProcess.stderr.on('data', (data) => {
    console.error(`Python stderr: ${data}`);
  });
  
  pythonProcess.on('close', (code) => {
    console.log(`Python process exited with code ${code}`);
    res.json({ message: "File uploaded and processed.", output: scriptOutput });
  });
});

// PROFILE IMAGE ROUTE: Must be above the catch-all route
app.get('/profileImage', async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).send("Email query parameter is required.");
  }
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.profileImage) {
      res.set('Content-Type', 'image/jpeg');
      return res.send(user.profileImage);
    } else {
      return res.status(404).send("Image not found");
    }
  } catch (error) {
    console.error("Error fetching profile image:", error);
    return res.status(500).send("Server error");
  }
});

// USER PLOT ENDPOINTS
app.get('/userPlot1', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent1) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent1);
    } else {
      return res.status(404).send("Plot 1 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 1:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot2', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent2) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent2);
    } else {
      return res.status(404).send("Plot 2 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 2:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot3', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent3) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent3);
    } else {
      return res.status(404).send("Plot 3 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 3:", error);
    return res.status(500).send("Server error");
  }
});

// Catch-all for SPA routes: serve index.html from the build folder
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

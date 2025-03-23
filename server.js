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
  profileImage: Buffer,
  plotContent1: String,
  plotContent2: String,
  plotContent3: String,
  plotContent4: String,
  plotContent5: String,
  plotContent6: String,
  plotContent7: String,
  plotContent8: String,
  plotContent9: String,
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
  
  // Folder containing the plotting scripts
  const scriptsDir = path.join(__dirname, 'plotting_scripts');
  
  let scriptFiles;
  try {
    scriptFiles = fs.readdirSync(scriptsDir).filter(file => file.endsWith('.py'));
  } catch (err) {
    console.error("Error reading plotting_scripts directory:", err);
    return res.status(500).json({ message: "Error reading plotting scripts directory." });
  }
  
  if (scriptFiles.length === 0) {
    return res.status(404).json({ message: "No plotting scripts found." });
  }
  
  // Create a promise for each script execution
  const scriptPromises = scriptFiles.map(script => {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(scriptsDir, script);
      const proc = spawn('python', [scriptPath, filePath]);
      
      let output = "";
      let errorOutput = "";
      
      proc.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      proc.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      proc.on('close', (code) => {
        if (code === 0) {
          console.log(`${script} completed successfully.`);
          resolve({ script, output });
        } else {
          console.error(`${script} exited with code ${code}. Error: ${errorOutput}`);
          reject({ script, code, error: errorOutput });
        }
      });
    });
  });
  
  // Wait for all scripts to settle
  Promise.allSettled(scriptPromises)
    .then(results => {
      const successes = results.filter(r => r.status === 'fulfilled').map(r => r.value);
      const failures = results.filter(r => r.status === 'rejected').map(r => r.reason);
      
      console.log("Scripts execution results:", { successes, failures });
      res.json({ message: "File uploaded and scripts executed.", successes, failures });
    })
    .catch(err => {
      console.error("Error running scripts:", err);
      res.status(500).json({ message: "Error executing plotting scripts." });
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

app.get('/userPlot4', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent4) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent4);
    } else {
      return res.status(404).send("Plot 4 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 4:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot5', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent5) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent5);
    } else {
      return res.status(404).send("Plot 5 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 5:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot6', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent6) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent6);
    } else {
      return res.status(404).send("Plot 6 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 6:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot7', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent7) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent7);
    } else {
      return res.status(404).send("Plot 7 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 7:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot8', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent8) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent8);
    } else {
      return res.status(404).send("Plot 8 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 8:", error);
    return res.status(500).send("Server error");
  }
});

app.get('/userPlot9', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Email query parameter is required.");
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (user && user.plotContent9) {
      res.set('Content-Type', 'text/html');
      return res.send(user.plotContent9);
    } else {
      return res.status(404).send("Plot 9 not found");
    }
  } catch (error) {
    console.error("Error fetching plot 9:", error);
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

import fs from 'fs';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// Convert ES module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read the current user's email from currentUser.txt
const currentUserFile = path.join(__dirname, 'currentUser.txt');
let currentUserEmail;
try {
  currentUserEmail = fs.readFileSync(currentUserFile, 'utf-8').trim();
} catch (err) {
  console.error("Error reading currentUser.txt:", err);
  process.exit(1);
}

if (!currentUserEmail) {
  console.log("No logged-in user found. Exiting updatePlot script.");
  process.exit(0);
}

// Connect to MongoDB using your environment variable (mongodb_urri)
mongoose.connect(process.env.mongodb_urri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB Connection Error:', err);
    process.exit(1);
  });

// Define the User schema with fields for plot content
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  profileImage: Buffer, // Field to store the image
  plotContent1: String, // Field for plot1.html content
  plotContent2: String, // Field for plot2.html content
  plotContent3: String, // Field for plot3.html content
});
const User = mongoose.model('User', userSchema);

async function updateAllPlots() {
  try {
    // List of plot files
    const plotFiles = ['plot1.html', 'plot2.html', 'plot3.html'];
    const plotContents = {};
    
    // Loop through each file and read its content if it exists
    for (const fileName of plotFiles) {
      const filePath = path.join(__dirname, fileName);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf-8');
        // Map file name to the corresponding field name: plot1.html -> plotContent1, etc.
        const fieldName = 'plotContent' + fileName.charAt(4);
        plotContents[fieldName] = content;
      } else {
        console.log(`File ${fileName} not found. Skipping update for this file.`);
      }
    }

    // Update the user document with the plot contents
    const result = await User.updateOne(
      { email: currentUserEmail.trim().toLowerCase() },
      { $set: plotContents }
    );
    console.log('Update result:', result);
    
    // Optionally, delete the local plot files after updating
    for (const fileName of plotFiles) {
      const filePath = path.join(__dirname, fileName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`Deleted ${fileName}`);
      }
    }
    
  } catch (error) {
    console.error("Error updating plot content:", error);
  } finally {
    mongoose.connection.close();
  }
}

updateAllPlots();

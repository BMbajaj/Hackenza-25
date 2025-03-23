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
  console.log("No logged-in user found. Exiting update script.");
  process.exit(0);
}

// Connect to MongoDB using your environment variable (mongodb_urri)
mongoose.connect(process.env.mongodb_urri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => {
  console.error("MongoDB Connection Error:", err);
  process.exit(1);
});

// Define the User schema with nine plotContent fields
const userSchema = new mongoose.Schema({
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
const User = mongoose.model("User", userSchema);

async function updatePlots() {
  try {
    // Loop through plot files 1 through 9
    const updates = {};
    for (let i = 1; i <= 9; i++) {
      const fileName = `plot${i}.html`;
      const filePath = path.join(__dirname, fileName);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf-8');
        updates[`plotContent${i}`] = content;
      } else {
        console.log(`${fileName} not found. Skipping update for this file.`);
      }
    }
    
    if (Object.keys(updates).length === 0) {
      console.log("No plot files found. Exiting.");
      process.exit(0);
    }
    
    // Update the current user's document in MongoDB with the new plot content
    const result = await User.updateOne(
      { email: currentUserEmail.toLowerCase().trim() },
      { $set: updates }
    );
    console.log("Update result:", result);
    
    // Delete each plot file after successful update
    for (let i = 1; i <= 9; i++) {
      const fileName = `plot${i}.html`;
      const filePath = path.join(__dirname, fileName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`${fileName} deleted successfully.`);
      }
    }
  } catch (error) {
    console.error("Error updating plot content:", error);
  } finally {
    mongoose.connection.close();
  }
}

updatePlots();

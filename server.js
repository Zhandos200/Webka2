require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs'); // For password hashing
const session = require('express-session'); // For session management
const multer = require('multer'); // For file upload

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Express Session Middleware
app.use(session({
    secret: 'secretkey', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Change to true if using HTTPS
}));

// Set view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// MongoDB Connection
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('Error connecting to MongoDB:', err));

// Mongoose Schema and Model
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    age: Number,
    password: String,  // Hashed password
    failedAttempts: { type: Number, default: 0 }, // Counter for failed login attempts
    accountLocked: { type: Boolean, default: false }, // Whether account is locked
    profilePicture: { type: String }  // Store file path for the profile picture
});

const User = mongoose.model('User', userSchema);

// Middleware to check authentication
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Set up multer storage configuration for profile picture upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/'); // Store images in the 'public/uploads' folder
    },
    filename: (req, file, cb) => {
        const fileExtension = path.extname(file.originalname);
        cb(null, `${Date.now()}${fileExtension}`); // Store with unique name
    }
});

const upload = multer({ storage: storage });

// Home Route (Only accessible when logged in)
app.get('/', requireAuth, async (req, res) => {
    try {
        let { search, sortBy, order } = req.query;
        let filter = {};

        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } }, 
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        let sortOptions = {};
        if (sortBy) {
            sortOptions[sortBy] = order === 'desc' ? -1 : 1;
        }

        const users = await User.find(filter).sort(sortOptions);
        res.render('index', { users, user: req.session.userName }); // Pass user info to EJS
    } catch (err) {
        res.status(500).send('Error fetching users');
    }
});

// Registration Route
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, age, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, age, password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send('Error registering user');
    }
});

// Login Route
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.send('Invalid credentials');
        }

        // If the account is locked
        if (user.accountLocked) {
            return res.send('Your account is locked due to multiple failed login attempts. Please contact support.');
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            user.failedAttempts += 1;
            if (user.failedAttempts >= 5) {
                user.accountLocked = true;
                await user.save();
                return res.send('Your account is locked due to multiple failed login attempts. Please contact support.');
            }
            await user.save();
            return res.send('Invalid credentials');
        }

        // Reset failed attempts on successful login
        user.failedAttempts = 0;
        await user.save();

        req.session.userId = user._id;
        req.session.userName = user.name;
        res.redirect('/');
    } catch (err) {
        res.status(500).send('Error logging in');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Delete User Route
app.post('/users/delete/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await User.findByIdAndDelete(id);
        res.redirect('/');  // Redirect after deletion
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting user');
    }
});

// Route to render and handle user update form
app.get('/users/update/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Render the update form with user data pre-filled
        res.render('update', { user });
    } catch (err) {
        res.status(500).send('Error fetching user');
    }
});

// Route to handle updating user data
app.post('/users/update/:id', upload.single('profilePicture'), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, age } = req.body;

        const updatedData = {
            name,
            email,
            age
        };

        // If a profile picture is uploaded, add its filename to the user's data
        if (req.file) {
            updatedData.profilePicture = `/uploads/${req.file.filename}`;
        }

        const updatedUser = await User.findByIdAndUpdate(id, updatedData, { new: true });

        if (!updatedUser) {
            return res.status(404).send('User not found');
        }

        res.redirect('/');  // Redirect to home page after update
    } catch (err) {
        res.status(500).send('Error updating user');
    }
});
// Profile Route (accessible after login)
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId); // Fetch user by session ID
        if (!user) {
            return res.status(404).send('User not found');
        }

        res.render('profile', { user });
    } catch (err) {
        res.status(500).send('Error fetching user profile');
    }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

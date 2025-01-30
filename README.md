# Webka2 - User Management System

Webka2 is a web application built using **Node.js**, **Express**, **MongoDB**, and **EJS** for the frontend. It allows users to register, log in, view, edit, delete user profiles, upload profile pictures, and manage user data. The application also includes additional features like account locking after multiple failed login attempts and form validation.

## Features

- **User Registration**: Users can register with their name, email, age, and password.
- **User Login**: Users can log in to the application using their email and password.
- **Profile Management**: Users can view and update their profile information.
- **Account Locking**: After 5 failed login attempts, an account is locked.
- **Profile Picture Upload**: Users can upload a profile picture which will be displayed on their profile page.
- **Form Validation**: The app ensures that all required fields are filled out, and checks password length during registration and login.
- **Error Handling**: The app provides error messages for invalid credentials and missing fields.

## Installation

Follow these steps to get your development environment up and running:

### 1. Clone the Repository


git clone https://github.com/yourusername/Webka2.git

2. Install Dependencies
Navigate to the project directory and run the following command to install the required dependencies:

npm install
3. Set Up Environment Variables
Create a .env file in the root directory of the project and add your environment variables:

plaintext

MONGO_URI=your_mongodb_connection_string
PORT=3000
4. Run the Application
To start the development server, run:


npm start
The application will be available at http://localhost:3000.

Usage
1. User Registration:
Navigate to /register to create a new user account.
Fill out the registration form with your name, email, age, and password.
2. Login:
Navigate to /login to log in with your email and password.
After successful login, you'll be redirected to the home page where you can view and manage user profiles.
3. Profile Page:
Each user has their own profile page where you can update your profile details and upload a profile picture.
4. Account Locking:
If you enter the wrong password 5 times in a row, your account will be temporarily locked.
Contributing
Contributions are welcome! If you'd like to contribute to this project, please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature-branch).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature-branch).
Open a pull request.
License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Express.js
MongoDB
EJS
Bcrypt.js
multer for handling file uploads
vbnet

### Customization:
- **MONGO_URI**: You'll need to replace `your_mongodb_connection_string` with your actual MongoDB connection string.
- **Screenshots/Images**: If you want to add any screenshots or images, you can place them in a `docs` folder and link to them in the `README.md` (e.g., `![Home Page](docs/screenshot1.png)`).

This is a basic structure, and you can modify it based on the specific needs of your project. If you have any additional features or specific instructions for users or developers, feel free to add them in the relevant sections!
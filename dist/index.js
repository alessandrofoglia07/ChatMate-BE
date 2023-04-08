import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './models/users.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());
const dbURI = process.env.ATLAS_URI;
const connectToDB = async () => {
    try {
        await mongoose.connect(dbURI);
        console.log('Connected to MongoDB');
        const port = process.env.PORT || 5000;
        app.listen(port, () => console.log(`Server started on port ${port}`));
    }
    catch (err) {
        console.log(err);
    }
};
connectToDB();
const SaltRounds = 10;
let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASSWORD,
    },
});
const checkIfTokenIsExpired = async () => {
    try {
        const today = new Date();
        const allUsers = await User.find();
        allUsers.forEach(async (user) => {
            if (user.verificationTokenExpires < today) {
                await User.deleteOne({ _id: user._id });
                console.log('User deleted (token expired)');
            }
        });
    }
    catch (err) {
        console.log(err);
    }
};
const sendVerificationEmail = (email, verificationToken) => {
    const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: 'Verify your email',
        text: `Please click on the following link to verify your email: http://localhost:3000/verify/${verificationToken}`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.log(err);
        }
        else {
            console.log(`Verification email sent: ${info.response}`);
        }
    });
};
const createTomorrowsDate = () => {
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    return tomorrow;
};
app.post('/api/signup', async (req, res) => {
    checkIfTokenIsExpired();
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const verificationToken = uuidv4();
    try {
        const isUserAlreadyRegistered = await User.find({ email: email });
        if (isUserAlreadyRegistered.length > 0) {
            res.send({ message: 'Email is already registered' });
            return;
        }
        else {
            bcrypt.hash(password, SaltRounds, async (err, hash) => {
                if (err) {
                    console.log(err);
                    res.status(500).send('Error');
                }
                else {
                    const user = new User({
                        username: username,
                        email: email,
                        password: hash,
                        verificationToken: verificationToken,
                        verified: false,
                        verificationTokenExpires: createTomorrowsDate(),
                    });
                    try {
                        const result = await user.save();
                        res.send({ message: 'User created' });
                        console.log('User added');
                        sendVerificationEmail(email, verificationToken);
                    }
                    catch (err) {
                        console.log(err);
                        res.status(500).send('Error');
                    }
                }
            });
        }
    }
    catch (err) {
        console.log(err);
    }
});
app.get('/api/verify/:token', async (req, res) => {
    checkIfTokenIsExpired();
    const token = req.params.token;
    console.log('Verificating user...');
    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            console.log('User not found');
            return res.status(404).send('User not found');
        }
        if (user.verified) {
            console.log('User already verified');
            return res.status(400).send('User already verified');
        }
        await User.updateOne({ _id: user._id }, {
            $set: { verified: true },
            $unset: { verificationToken: 1, verificationTokenExpires: 1 }
        });
        console.log('User verified');
        return res.send('User verified');
    }
    catch (err) {
        console.log(err);
    }
});
app.post('/api/login', async (req, res) => {
    checkIfTokenIsExpired();
    const email = req.body.email;
    const password = req.body.password;
    try {
        await User.findOne({ email: email }, async (err, user) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error');
            }
            else {
                if (!user) {
                    console.log('User not found');
                    return res.status(404).send('User not found');
                }
                if (!user.verified) {
                    console.log('User not verified');
                    return res.status(401).send('User not verified');
                }
                bcrypt.compare(password, user.password, async (err, result) => {
                    if (err) {
                        console.log(err);
                        return res.status(500).send('Error');
                    }
                    else {
                        if (result) {
                            const username = user.username;
                            const id = user._id;
                            const accessToken = jwt.sign({ id: id, email: email, username: username }, process.env.JWT_SECRET);
                            res.status(200).send({ message: 'Login successful', accessToken: accessToken, id: id, username: username, email: email });
                        }
                        else {
                            console.log('Incorrect password');
                            return res.status(401).send('Incorrect password');
                        }
                    }
                });
            }
        });
    }
    catch (err) {
        console.log(err);
    }
});
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    }
    else {
        res.sendStatus(401);
    }
};
/* how to use authenticateJWT
app.get('/api/protected', authenticateJWT, (req: any, res: Response) => {
    res.send('Protected route');
});
*/ 

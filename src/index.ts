import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './models/users.js';
import Message from './models/messages.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import http from 'http';
import { Server } from 'socket.io';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
    }
});

app.use(express.json());
app.use(cors());

const dbURI = process.env.ATLAS_URI as string;

const connectToDB = async () => {
    try {
        await mongoose.connect(dbURI);
        console.log('Connected to MongoDB');
        const port = process.env.PORT || 5000;
        server.listen(port, () => console.log(`Server started on port ${port}`));
    } catch (err) {
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
        allUsers.forEach(async (user: any) => {
            if (user.verificationTokenExpires < today) {
                await User.deleteOne({ _id: user._id });
                console.log('User deleted (token expired)');
            }
        });
    } catch (err) {
        console.log(err);
    }
};

const sendVerificationEmail = (email: string, verificationToken: string) => {
    const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: 'Verify your email',
        text: `Please click on the following link to verify your email: http://localhost:3000/verify/${verificationToken}`,
    };

    transporter.sendMail(mailOptions, (err: Error | null, info: any) => {
        if (err) {
            console.log(err);
        } else {
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

const CHAT_BOT = 'ChatBot';
let chatRoom = '';
let allUsers: any[] = [];

// listen for socket connections from client
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // listen for user to join a room
    socket.on('join_room', async (data: { room: string, username: string; }) => {
        const { room, username } = data;
        socket.join(room);
        console.log(`User ${username} joined room ${room}`);

        socket.on('send_message', (data: { username: string, room: string, message: string; }) => {
            const { message, username, room } = data;
            io.in(room).emit('receive_message', data); // send message to all users in the room
            // save message to db
            const newMessage = new Message({
                room: room,
                message: message,
                username: username,
            });
            newMessage.save();
        });

        socket.emit('send_message', {
            username: CHAT_BOT,
            room: room,
            message: `${username} has joined the room`,
        });

        // get last 100 messages from db
        const last100Messages = await Message.find({ room: room }).sort({ createdAt: -1 }).limit(100);
        socket.emit('last_100_messages', last100Messages.reverse());


        chatRoom = room;
        allUsers.push({ id: socket.id, username: username, room: room });
        let chatRoomUsers = allUsers.filter((user: { room: string; }) => user.room === chatRoom);
        socket.to(room).emit('chatroom_users', chatRoomUsers);
        socket.emit('chatroom_users', chatRoomUsers);

    });
});

app.post('/api/signup', async (req: Request, res: Response) => {
    checkIfTokenIsExpired();
    const username: string = req.body.username;
    const email: string = req.body.email;
    const password: string = req.body.password;
    const verificationToken: string = uuidv4();

    try {
        const isUserAlreadyRegistered = await User.find({ email: email });
        if (isUserAlreadyRegistered.length > 0) {
            res.send({ message: 'Email is already registered' });
            return;
        } else {
            bcrypt.hash(password, SaltRounds, async (err: Error | undefined, hash: string) => {
                if (err) {
                    console.log(err);
                    res.status(500).send('Error');
                } else {
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
                    } catch (err) {
                        console.log(err);
                        res.status(500).send('Error');
                    }
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.get('/api/verify/:token', async (req: Request, res: Response) => {
    checkIfTokenIsExpired();
    const token: string = req.params.token;
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
        await User.updateOne(
            { _id: user._id },
            {
                $set: { verified: true },
                $unset: { verificationToken: 1, verificationTokenExpires: 1 }
            }
        );
        console.log('User verified');
        return res.send('User verified');
    } catch (err) {
        console.log(err);
    }
});

app.post('/api/login', async (req: Request, res: Response) => {
    checkIfTokenIsExpired();
    const email: string = req.body.email;
    console.log(email);
    const password: string = req.body.password;

    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            console.log('User not found');
            return res.status(404).send('User not found');
        }
        if (!user.verified) {
            console.log('User not verified');
            return res.status(401).send('User not verified');
        }
        bcrypt.compare(password, user.password, async (err: Error | undefined, result: boolean) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error');
            } else {
                if (result) {
                    const username = user.username;
                    const id = user._id;
                    const accessToken = jwt.sign({ id: id, email: email, username: username }, process.env.JWT_SECRET as string);
                    res.status(200).send({ message: 'Login successful', accessToken: accessToken, id: id, username: username, email: email });
                    console.log('Login successful');
                } else {
                    console.log('Incorrect password');
                    return res.status(401).send('Incorrect password');
                }
            }
        });
    } catch (err) {
        console.log(err);
    }
});

const authenticateJWT = (req: any, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.JWT_SECRET as string, (err: any, user: any) => {
            if (err) {
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};
/* how to use authenticateJWT
app.get('/api/protected', authenticateJWT, (req: any, res: Response) => {
    res.send('Protected route');
});
*/
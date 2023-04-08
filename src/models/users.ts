import { Schema, model, Document } from "mongoose";

interface IUser {
    username: string;
    email: string;
    password: string;
    verificationToken: string;
    accessToken: string;
    verified: boolean;
    verificationTokenExpires: Date;
}

interface IUserModel extends IUser, Document { }

const userSchema = new Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    verificationToken: { type: String, required: false },
    accessToken: { type: String, required: false },
    verified: { type: Boolean, required: true },
    verificationTokenExpires: { type: Date, required: false },
}, { timestamps: true });

const User = model<IUserModel>('User', userSchema);

export default User;
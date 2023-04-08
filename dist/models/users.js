import { Schema, model } from "mongoose";
const userSchema = new Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    verificationToken: { type: String, required: false },
    accessToken: { type: String, required: false },
    verified: { type: Boolean, required: true },
    verificationTokenExpires: { type: Date, required: false },
}, { timestamps: true });
const User = model('User', userSchema);
export default User;

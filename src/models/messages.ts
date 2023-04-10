import { Schema, model, Document } from "mongoose";

interface IMessage {
    room: string;
    message: string;
    username: string;
}

interface IMessageModel extends IMessage, Document { }

const messageSchema = new Schema({
    room: { type: String, required: true },
    message: { type: String, required: true },
    username: { type: String, required: true },
}, { timestamps: true });

const Message = model<IMessageModel>('Message', messageSchema);

export default Message;
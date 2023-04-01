import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import isEmail from "validator/lib/isEmail.js";
import IEmail from "../interfaces/Email.interface";

// adding schema methods here
export interface IEmailDocument extends IEmail, Document {}

// adding statics methods here
export type IEmailModel = Model<IEmailDocument>;

// schema definition
const EmailSchema = new Schema<IEmailDocument, object, IEmailDocument>(
	{
		to: [{ type: String, index: true, lowercase: true, trim: true, validate: [isEmail, "Invalid Email Address"] }],
		from: { type: String, index: true, lowercase: true, trim: true, validate: [isEmail, "Invalid Email Address"] },
		html: { type: String },
		text: { type: String },
		subject: { type: String, required: true },
	},
	{ timestamps: true }
);

// modal definition
const EmailModal = model<IEmailDocument, PaginateModel<IEmailDocument> & IEmailModel>("Email", EmailSchema);

export default EmailModal;

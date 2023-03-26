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
		from: {
			type: String,
			index: true,
			lowercase: true,
			trim: true,
			validate: [isEmail, "Invalid Email Address"],
		},
		to: [
			{
				type: String,
				index: true,
				lowercase: true,
				trim: true,
				validate: [isEmail, "Invalid Email Address"],
			},
		],
		subject: { type: String, required: true },
		html: { type: String },
		text: { type: String },
	},
	{ timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

// modal definition
const EmailModal = model<IEmailDocument, PaginateModel<IEmailDocument> & IEmailModel>("Email", EmailSchema);

export default EmailModal;

import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import IToken from "../interfaces/Token.interface";
import vars from "../utils/vars";

// adding schema methods here
export interface ITokenDocument extends IToken, Document {}

// adding statics methods here
export type ITokenModel = Model<ITokenDocument>;

// schema definition
const TokenSchema = new Schema<ITokenDocument, object, ITokenDocument>(
	{
		user: { type: Schema.Types.ObjectId, required: true, ref: "User" },
		kind: { type: String, required: true, enum: [...Object.values(vars.tokenTypes)] },
		token: { type: String, required: true, index: true },
		expire_at: { type: Date },
	},
	{ timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

// modal definition
const TokenModal = model<ITokenDocument, PaginateModel<ITokenDocument> & ITokenModel>("Token", TokenSchema);

export default TokenModal;

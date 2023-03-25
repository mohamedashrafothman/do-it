import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import ISession from "../interfaces/Session.interface";

// adding schema methods here
export interface ISessionDocument extends ISession, Document {}

// adding statics methods here
export type ISessionModel = Model<ISessionDocument>;

// schema definition
const SessionSchema = new Schema<ISessionDocument, object, ISessionDocument>(
	{},
	{ timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

// modal definition
const SessionModal = model<ISessionDocument, PaginateModel<ISessionDocument> & ISessionModel>("Session", SessionSchema);

export default SessionModal;

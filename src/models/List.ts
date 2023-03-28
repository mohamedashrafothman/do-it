import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import slug from "mongoose-slug-updater";
import IList from "../interfaces/List.interface";

// adding schema methods here
export interface IListDocument extends IList, Document {}

// adding statics methods here
export type IListModel = Model<IListDocument>;

// schema definition
const ListSchema = new Schema<IListDocument, object, IListDocument>(
	{
		user: { type: Schema.Types.ObjectId, required: true, ref: "User" },
		name: { type: String, trim: true, required: true },
		slug: { type: String, slug: "name", unique: true, index: true, slugPaddingSize: 6 },
		emoji: { type: String, required: true },
	},
	{ timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

// schema plugins
ListSchema.plugin(slug);

// modal definition
const ListModal = model<IListDocument, PaginateModel<IListDocument> & IListModel>("List", ListSchema);

export default ListModal;

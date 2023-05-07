import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import { SoftDeleteInterface, SoftDeleteModel } from "mongoose-delete";
import slug from "mongoose-slug-updater";
import IList from "../interfaces/List.interface";

// adding schema methods here
export interface IListDocument extends SoftDeleteInterface, IList, Document {}

// adding statics methods here
export type IListModel = Model<IListDocument>;

// schema definition
const ListSchema = new Schema<IListDocument, object, IListDocument>(
	{
		name: { type: String, trim: true, required: true },
		slug: { type: String, slug: "name", unique: true, index: true, slugPaddingSize: 6 },
		user: { type: Schema.Types.ObjectId, required: true, ref: "User", autopopulate: true },
		emoji: { type: String, required: true },
	},
	{ timestamps: true }
);

// schema plugins
ListSchema.plugin(slug);

// modal definition
const ListModal = model<IListDocument, PaginateModel<IListDocument> & SoftDeleteModel<IListDocument> & IListModel>(
	"List",
	ListSchema
);

export default ListModal;

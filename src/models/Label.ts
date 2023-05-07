import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import { SoftDeleteInterface, SoftDeleteModel } from "mongoose-delete";
import slug from "mongoose-slug-updater";
import ILabel from "../interfaces/Label.interface";

// adding schema methods here
export interface ILabelDocument extends SoftDeleteInterface, ILabel, Document {}

// adding statics methods here
export type ILabelModel = Model<ILabelDocument>;

// schema definition
const LabelSchema = new Schema<ILabelDocument, object, ILabelDocument>(
	{
		name: { type: String, trim: true, required: true },
		slug: { type: String, slug: "name", unique: true, index: true, slugPaddingSize: 6 },
		user: { type: Schema.Types.ObjectId, required: true, ref: "User", autopopulate: true },
		emoji: { type: String, required: true },
	},
	{ timestamps: true }
);

// schema plugins
LabelSchema.plugin(slug);

// modal definition
const LabelModal = model<ILabelDocument, PaginateModel<ILabelDocument> & SoftDeleteModel<ILabelDocument> & ILabelModel>(
	"Label",
	LabelSchema
);

export default LabelModal;

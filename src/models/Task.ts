import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import MongooseDelete, { SoftDeleteModel } from "mongoose-delete";
import slug from "mongoose-slug-updater";
import ITask from "../interfaces/Task.interface";

// adding schema methods here
export interface ITaskDocument extends ITask, Document {}

// adding statics methods here
export type ITaskModel = Model<ITaskDocument>;

// schema definition
const TaskSchema = new Schema<ITaskDocument, object, ITaskDocument>(
	{
		name: { type: String, trim: true, required: true },
		slug: { type: String, slug: "name", unique: true, index: true, slugPaddingSize: 6 },
		user: { type: Schema.Types.ObjectId, required: true, ref: "User" },
		list: { type: Schema.Types.ObjectId, required: true, ref: "List" },
		steps: [{ type: Schema.Types.ObjectId, required: true, ref: "Steps" }],
		labels: [{ type: Schema.Types.ObjectId, ref: "Label" }],
	},
	{ timestamps: true }
);

// schema plugins
TaskSchema.plugin(slug);
TaskSchema.plugin(MongooseDelete, { deletedAt: true, deletedBy: true, overrideMethods: true });

// modal definition
const TaskModal = model<ITaskDocument, PaginateModel<ITaskDocument> & SoftDeleteModel<ITaskDocument> & ITaskModel>(
	"Task",
	TaskSchema
);

export default TaskModal;

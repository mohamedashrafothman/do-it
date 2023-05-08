import { AggregatePaginateModel, Document, Model, PaginateModel, Schema, model } from "mongoose";
import { SoftDeleteInterface, SoftDeleteModel } from "mongoose-delete";
import ITask from "../interfaces/Task.interface";

// adding schema methods here
export interface ITaskDocument extends SoftDeleteInterface, ITask, Document {}

// adding statics methods here
export type ITaskModel = Model<ITaskDocument>;

// schema definition
const TaskSchema = new Schema<ITaskDocument, object, ITaskDocument>(
	{
		name: { type: String, trim: true, required: true },
		slug: { type: String, slug: "name", unique: true, index: true, slugPaddingSize: 6 },
		user: { type: Schema.Types.ObjectId, required: true, ref: "User", autopopulate: true },
		list: { type: Schema.Types.ObjectId, required: true, ref: "List", autopopulate: true },
		steps: [{ type: Schema.Types.ObjectId, required: true, ref: "Step", autopopulate: true }],
		labels: [{ type: Schema.Types.ObjectId, ref: "Label", autopopulate: true }],
	},
	{ timestamps: true }
);

// modal definition
const TaskModal = model<
	ITaskDocument,
	PaginateModel<ITaskDocument> & AggregatePaginateModel<ITaskDocument> & SoftDeleteModel<ITaskDocument> & ITaskModel
>("Task", TaskSchema);

export default TaskModal;

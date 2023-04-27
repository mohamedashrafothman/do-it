import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import mongooseAutopopulate from "mongoose-autopopulate";
import IStep from "../interfaces/Step.interface";

// adding schema methods here
export interface IStepDocument extends IStep, Document {}

// adding statics methods here
export type IStepModel = Model<IStepDocument>;

// schema definition
const StepSchema = new Schema<IStepDocument, object, IStepDocument>(
	{
		user: { type: Schema.Types.ObjectId, required: true, ref: "User", autopopulate: true },
		title: { type: String, required: true, trim: true },
		dueDate: { type: Date },
		completed: { type: Boolean, default: false },
		orderInList: { type: Number, required: true },
		totalRepeatCount: { type: Number, default: 1 },
		currentRepeatCount: { type: Number, default: 1 },
	},
	{ timestamps: true }
);

// schema plugins
StepSchema.plugin(mongooseAutopopulate);

// modal definition
const StepModal = model<IStepDocument, PaginateModel<IStepDocument> & IStepModel>("Step", StepSchema);

export default StepModal;

import { Document, Model, PaginateModel, Schema, model } from "mongoose";
import { SoftDeleteModel } from "mongoose-delete";
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
		dueDate: { type: Date, required: true, default: Date.now },
		completed: { type: Boolean, default: false },
		order: { type: Number, required: true },
		totalRepeatCount: { type: Number, default: 1 },
		currentRepeatCount: { type: Number, default: 1 },
	},
	{ timestamps: true }
);

// modal definition
const StepModal = model<IStepDocument, PaginateModel<IStepDocument> & SoftDeleteModel<IStepDocument> & IStepModel>(
	"Step",
	StepSchema
);

export default StepModal;
